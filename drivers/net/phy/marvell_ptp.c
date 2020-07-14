// SPDX-License-Identifier: GPL-2.0+
/*
 * Marvell PTP driver for 88E1510, 88E1512, 88E1514 and 88E1518 PHYs
 *
 * Ideas taken from 88E6xxx DSA and DP83640 drivers. This file
 * implements the packet timestamping support only (PTP).  TAI
 * support is separate.
 */
#include <linux/if_vlan.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/net_tstamp.h>
#include <linux/phy.h>
#include <linux/ptp_classify.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/uaccess.h>

#include "marvell_ptp.h"
#include "marvell_tai.h"

#define TX_TIMEOUT_MS	40
#define RX_TIMEOUT_MS	40

#define MARVELL_PAGE_PTP_PORT_1			8
#define PTP1_PORT_CONFIG_0			0
#define PTP1_PORT_CONFIG_0_DISTSPECCHECK	BIT(11)
#define PTP1_PORT_CONFIG_0_DISTSOVERWRITE	BIT(1)
#define PTP1_PORT_CONFIG_0_DISPTP		BIT(0)
#define PTP1_PORT_CONFIG_1			1
#define PTP1_PORT_CONFIG_1_IPJUMP(x)		(((x) & 0x3f) << 8)
#define PTP1_PORT_CONFIG_1_ETJUMP(x)		((x) & 0x1f)
#define PTP1_PORT_CONFIG_2			2
#define PTP1_PORT_CONFIG_2_DEPINTEN		BIT(1)
#define PTP1_PORT_CONFIG_2_ARRINTEN		BIT(0)
#define PTP1_ARR_STATUS0			8
#define PTP1_ARR_STATUS1			12

#define MARVELL_PAGE_PTP_PORT_2			9
#define PTP2_DEP_STATUS				0

struct marvell_ptp_cb {
	unsigned long timeout;
	u16 seq;
};
#define MARVELL_PTP_CB(skb)	((struct marvell_ptp_cb *)(skb)->cb)

struct marvell_rxts {
	struct list_head node;
	u64 ns;
	u16 seq;
};

struct marvell_ptp {
	struct marvell_tai *tai;
	struct list_head tai_node;
	struct phy_device *phydev;
	struct mii_timestamper mii_ts;

	/* We only support one outstanding transmit skb */
	struct sk_buff *tx_skb;
	enum hwtstamp_tx_types tx_type;

	struct mutex rx_mutex;
	struct list_head rx_free;
	struct list_head rx_pend;
	struct sk_buff_head rx_queue;
	enum hwtstamp_rx_filters rx_filter;
	struct marvell_rxts rx_ts[64];

	struct delayed_work ts_work;
};

struct marvell_ts {
	u32 time;
	u16 stat;
#define MV_STATUS_INTSTATUS_MASK		0x0006
#define MV_STATUS_INTSTATUS_NORMAL		0x0000
#define MV_STATUS_VALID				BIT(0)
	u16 seq;
};

/* Read the status, timestamp and PTP common header sequence from the PHY.
 * Apparently, reading these are atomic, but there is no mention how the
 * PHY treats this access as atomic. So, we set the DisTSOverwrite bit
 * when configuring the PHY.
 */
static int marvell_read_tstamp(struct phy_device *phydev,
			       struct marvell_ts *ts,
			       uint8_t page, uint8_t reg)
{
	int oldpage;
	int ret;

	/* Read status register */
	oldpage = phy_select_page(phydev, page);
	if (oldpage >= 0) {
		ret = __phy_read(phydev, reg);
		if (ret < 0)
			goto restore;

		ts->stat = ret;
		if (!(ts->stat & MV_STATUS_VALID)) {
			ret = 0;
			goto restore;
		}

		/* Read low timestamp */
		ret = __phy_read(phydev, reg + 1);
		if (ret < 0)
			goto restore;

		ts->time = ret;

		/* Read high timestamp */
		ret = __phy_read(phydev, reg + 2);
		if (ret < 0)
			goto restore;

		ts->time |= ret << 16;

		/* Read sequence */
		ret = __phy_read(phydev, reg + 3);
		if (ret < 0)
			goto restore;

		ts->seq = ret;

		/* Clear valid */
		__phy_write(phydev, reg, 0);
	}
restore:
	return phy_restore_page(phydev, oldpage, ret);
}

/* Shouldn't the ptp/networking provide this? */
static u8 *ptp_header(struct sk_buff *skb, int type)
{
	u8 *data = skb_mac_header(skb);
	u8 *ptr = data;

	if (type & PTP_CLASS_VLAN)
		ptr += VLAN_HLEN;

	switch (type & PTP_CLASS_PMASK) {
	case PTP_CLASS_IPV4:
		ptr += IPV4_HLEN(ptr) + UDP_HLEN;
		break;

	case PTP_CLASS_IPV6:
		ptr += IP6_HLEN + UDP_HLEN;
		break;

	case PTP_CLASS_L2:
		break;

	default:
		return NULL;
	}

	if (skb->len < ptr - data + 34)
		return NULL;

	return ptr + ETH_HLEN;
}

/* Extract the sequence ID */
static u16 ptp_seqid(u8 *ptp_hdr)
{
	__be16 *seqp = (__be16 *)(ptp_hdr + OFF_PTP_SEQUENCE_ID);

	return be16_to_cpup(seqp);
}

static struct marvell_ptp *mii_ts_to_ptp(struct mii_timestamper *mii_ts)
{
	return container_of(mii_ts, struct marvell_ptp, mii_ts);
}

/* Deliver a skb with its timestamp back to the networking core */
static void marvell_ptp_rx(struct sk_buff *skb, u64 ns)
{
	struct skb_shared_hwtstamps *shhwtstamps = skb_hwtstamps(skb);

	memset(shhwtstamps, 0, sizeof(*shhwtstamps));
	shhwtstamps->hwtstamp = ns_to_ktime(ns);
	netif_rx(skb);
}

/* Get a rx timestamp entry. Try the free list, and if that fails,
 * steal the oldest off the pending list.
 */
static struct marvell_rxts *marvell_ptp_get_rxts(struct marvell_ptp *ptp)
{
	if (!list_empty(&ptp->rx_free))
		return list_first_entry(&ptp->rx_free, struct marvell_rxts,
					node);

	return list_last_entry(&ptp->rx_pend, struct marvell_rxts, node);
}

/* Check for a rx timestamp entry, try to find the corresponding skb and
 * deliver it, otherwise add the rx timestamp to the queue of pending
 * timestamps.
 */
static int marvell_ptp_rx_ts(struct marvell_ptp *ptp)
{
	struct marvell_rxts *rxts;
	struct marvell_ts ts;
	struct sk_buff *skb;
	bool found = false;
	u64 ns;
	int err;

	err = marvell_read_tstamp(ptp->phydev, &ts, MARVELL_PAGE_PTP_PORT_1,
				  PTP1_ARR_STATUS0);
	if (err <= 0)
		return 0;

	if ((ts.stat & MV_STATUS_INTSTATUS_MASK) !=
	    MV_STATUS_INTSTATUS_NORMAL) {
		dev_warn(&ptp->phydev->mdio.dev,
			 "rx timestamp overrun (%x)\n", ts.stat);
		return -1;
	}

	ns = marvell_tai_cyc2time(ptp->tai, ts.time);

	mutex_lock(&ptp->rx_mutex);

	/* Search the rx queue for a matching skb */
	skb_queue_walk(&ptp->rx_queue, skb) {
		if (MARVELL_PTP_CB(skb)->seq == ts.seq) {
			__skb_unlink(skb, &ptp->rx_queue);
			found = true;
			break;
		}
	}

	if (!found) {
		rxts = marvell_ptp_get_rxts(ptp);
		rxts->ns = ns;
		rxts->seq = ts.seq;
		list_move(&rxts->node, &ptp->rx_pend);
	}

	mutex_unlock(&ptp->rx_mutex);

	if (found)
		marvell_ptp_rx(skb, ns);

	return 1;
}

/* Check whether the packet is suitable for timestamping, and if so,
 * try to find a pending timestamp for it. If no timestamp is found,
 * queue the packet with a timeout.
 */
static bool marvell_ptp_rxtstamp(struct mii_timestamper *mii_ts,
				 struct sk_buff *skb, int type)
{
	struct marvell_ptp *ptp = mii_ts_to_ptp(mii_ts);
	struct marvell_rxts *rxts;
	bool found = false;
	u8 *ptp_hdr;
	u16 seqid;
	u64 ns;

	if (ptp->rx_filter == HWTSTAMP_FILTER_NONE)
		return false;

	ptp_hdr = ptp_header(skb, type);
	if (!ptp_hdr)
		return false;

	seqid = ptp_seqid(ptp_hdr);

	mutex_lock(&ptp->rx_mutex);

	/* Search the pending receive timestamps for a matching seqid */
	list_for_each_entry(rxts, &ptp->rx_pend, node) {
		if (rxts->seq == seqid) {
			found = true;
			ns = rxts->ns;
			/* Move this timestamp entry to the free list */
			list_move_tail(&rxts->node, &ptp->rx_free);
			break;
		}
	}

	if (!found) {
		/* Store the seqid and queue the skb. Do this under the lock
		 * to ensure we don't miss any timestamps appended to the
		 * rx_pend list.
		 */
		MARVELL_PTP_CB(skb)->seq = seqid;
		MARVELL_PTP_CB(skb)->timeout = jiffies +
			msecs_to_jiffies(RX_TIMEOUT_MS);
		__skb_queue_tail(&ptp->rx_queue, skb);
	}

	mutex_unlock(&ptp->rx_mutex);

	if (found) {
		/* We found the corresponding timestamp. If we can add the
		 * timestamp, do we need to go through the netif_rx()
		 * path, or would it be more efficient to add the timestamp
		 * and return "false" here?
		 */
		marvell_ptp_rx(skb, ns);
	} else {
		schedule_delayed_work(&ptp->ts_work, 2);
	}

	return true;
}

/* Move any expired skbs on to our own list, and then hand the contents of
 * our list to netif_rx() - this avoids calling netif_rx() with our
 * mutex held.
 */
static void marvell_ptp_rx_expire(struct marvell_ptp *ptp)
{
	struct sk_buff_head list;
	struct sk_buff *skb;

	__skb_queue_head_init(&list);

	mutex_lock(&ptp->rx_mutex);
	while ((skb = skb_dequeue(&ptp->rx_queue)) != NULL) {
		if (!time_is_before_jiffies(MARVELL_PTP_CB(skb)->timeout)) {
			__skb_queue_head(&ptp->rx_queue, skb);
			break;
		}
		__skb_queue_tail(&list, skb);
	}
	mutex_unlock(&ptp->rx_mutex);

	while ((skb = __skb_dequeue(&list)) != NULL)
		netif_rx(skb);
}

/* Complete the transmit timestamping; this is called to read the transmit
 * timestamp from the PHY, and report back the transmitted timestamp.
 */
static int marvell_ptp_txtstamp_complete(struct marvell_ptp *ptp)
{
	struct skb_shared_hwtstamps shhwtstamps;
	struct sk_buff *skb = ptp->tx_skb;
	struct marvell_ts ts;
	int err;
	u64 ns;

	err = marvell_read_tstamp(ptp->phydev, &ts, MARVELL_PAGE_PTP_PORT_2,
				  PTP2_DEP_STATUS);
	if (err < 0)
		goto fail;

	if (err == 0) {
		if (time_is_before_jiffies(MARVELL_PTP_CB(skb)->timeout)) {
			dev_warn(&ptp->phydev->mdio.dev,
				 "tx timestamp timeout\n");
			goto free;
		}
		return 0;
	}

	/* Check the status */
	if ((ts.stat & MV_STATUS_INTSTATUS_MASK) !=
	    MV_STATUS_INTSTATUS_NORMAL) {
		dev_warn(&ptp->phydev->mdio.dev,
			 "tx timestamp overrun (%x)\n", ts.stat);
		goto free;
	}

	/* Reject if the sequence number doesn't match */
	if (ts.seq != MARVELL_PTP_CB(skb)->seq) {
		dev_warn(&ptp->phydev->mdio.dev,
			 "tx timestamp unexpected sequence id\n");
		goto free;
	}

	ptp->tx_skb = NULL;

	/* Set the timestamp */
	ns = marvell_tai_cyc2time(ptp->tai, ts.time);
	memset(&shhwtstamps, 0, sizeof(shhwtstamps));
	shhwtstamps.hwtstamp = ns_to_ktime(ns);
	skb_complete_tx_timestamp(skb, &shhwtstamps);
	return 1;

fail:
	dev_err_ratelimited(&ptp->phydev->mdio.dev,
			    "failed reading PTP: %pe\n", ERR_PTR(err));
free:
	dev_kfree_skb_any(skb);
	ptp->tx_skb = NULL;
	return -1;
}

/* Check whether the skb will be timestamped on transmit; we only support
 * a single outstanding skb. Add it if the slot is available.
 */
static bool marvell_ptp_do_txtstamp(struct mii_timestamper *mii_ts,
				    struct sk_buff *skb, int type)
{
	struct marvell_ptp *ptp = mii_ts_to_ptp(mii_ts);
	u8 *ptp_hdr;

	if (ptp->tx_type != HWTSTAMP_TX_ON)
		return false;

	if (!(skb_shinfo(skb)->tx_flags & SKBTX_HW_TSTAMP))
		return false;

	ptp_hdr = ptp_header(skb, type);
	if (!ptp_hdr)
		return false;

	MARVELL_PTP_CB(skb)->seq = ptp_seqid(ptp_hdr);
	MARVELL_PTP_CB(skb)->timeout = jiffies +
		msecs_to_jiffies(TX_TIMEOUT_MS);

	if (cmpxchg(&ptp->tx_skb, NULL, skb) != NULL)
		return false;

	/* DP83640 marks the skb for hw timestamping. Since the MAC driver
	 * may call skb_tx_timestamp() but may not support timestamping
	 * itself, it may not set this flag. So, we need to do this here.
	 */
	skb_shinfo(skb)->tx_flags |= SKBTX_IN_PROGRESS;
	schedule_delayed_work(&ptp->ts_work, 2);

	return true;
}

static void marvell_ptp_txtstamp(struct mii_timestamper *mii_ts,
				 struct sk_buff *skb, int type)
{
	if (!marvell_ptp_do_txtstamp(mii_ts, skb, type))
		kfree_skb(skb);
}

static int marvell_ptp_hwtstamp(struct mii_timestamper *mii_ts,
				struct kernel_hwtstamp_config *config,
				struct netlink_ext_ack *extack)
{
	struct marvell_ptp *ptp = mii_ts_to_ptp(mii_ts);
	u16 cfg0 = PTP1_PORT_CONFIG_0_DISPTP;
	u16 cfg2 = 0;
	int err;

	if (config->flags)
		return -EINVAL;

	switch (config->tx_type) {
	case HWTSTAMP_TX_OFF:
		break;

	case HWTSTAMP_TX_ON:
		cfg0 = 0;
		cfg2 |= PTP1_PORT_CONFIG_2_DEPINTEN;
		break;

	default:
		return -ERANGE;
	}

	switch (config->rx_filter) {
	case HWTSTAMP_FILTER_NONE:
		break;

	case HWTSTAMP_FILTER_PTP_V1_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V1_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V1_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L4_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L4_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L4_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_L2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_L2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_L2_DELAY_REQ:
	case HWTSTAMP_FILTER_PTP_V2_EVENT:
	case HWTSTAMP_FILTER_PTP_V2_SYNC:
	case HWTSTAMP_FILTER_PTP_V2_DELAY_REQ:
		/* We accept 802.1AS, IEEE 1588v1 and IEEE 1588v2. We could
		 * filter on 802.1AS using the transportSpecific field, but
		 * that affects the transmit path too.
		 */
		config->rx_filter = HWTSTAMP_FILTER_SOME;
		cfg0 = 0;
		cfg2 |= PTP1_PORT_CONFIG_2_ARRINTEN;
		break;

	default:
		return -ERANGE;
	}

	err = phy_modify_paged(ptp->phydev, MARVELL_PAGE_PTP_PORT_1,
			       PTP1_PORT_CONFIG_0,
			       PTP1_PORT_CONFIG_0_DISPTP, cfg0);
	if (err)
		return err;

	err = phy_write_paged(ptp->phydev, MARVELL_PAGE_PTP_PORT_1,
			      PTP1_PORT_CONFIG_2, cfg2);
	if (err)
		return err;

	ptp->tx_type = config->tx_type;
	ptp->rx_filter = config->rx_filter;

	return 0;
}

static int marvell_ptp_ts_info(struct mii_timestamper *mii_ts,
			       struct ethtool_ts_info *ts_info)
{
	struct marvell_ptp *ptp = mii_ts_to_ptp(mii_ts);

	ts_info->so_timestamping = SOF_TIMESTAMPING_TX_HARDWARE |
				   SOF_TIMESTAMPING_RX_HARDWARE |
				   SOF_TIMESTAMPING_RAW_HARDWARE;
	ts_info->phc_index = ptp_clock_index(ptp->tai->ptp_clock);
	ts_info->tx_types = BIT(HWTSTAMP_TX_OFF) |
			    BIT(HWTSTAMP_TX_ON);
	ts_info->rx_filters = BIT(HWTSTAMP_FILTER_NONE) |
			      BIT(HWTSTAMP_FILTER_SOME);

	return 0;
}

static int marvell_ptp_port_config(struct phy_device *phydev)
{
	int err;

	/* Disable transport specific check (if the PTP common header)
	 * Disable timestamp overwriting (so we can read a stable entry.)
	 * Disable PTP
	 */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_PORT_1,
			      PTP1_PORT_CONFIG_0,
			      PTP1_PORT_CONFIG_0_DISTSPECCHECK |
			      PTP1_PORT_CONFIG_0_DISTSOVERWRITE |
			      PTP1_PORT_CONFIG_0_DISPTP);
	if (err < 0)
		return err;

	/* Set ether-type jump to 12 (to ether protocol)
	 * Set IP jump to 2 (to skip over ether protocol)
	 * Does this mean it won't pick up on VLAN packets?
	 */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_PORT_1,
			      PTP1_PORT_CONFIG_1,
			      PTP1_PORT_CONFIG_1_ETJUMP(12) |
			      PTP1_PORT_CONFIG_1_IPJUMP(2));
	if (err < 0)
		return err;

	/* Disable all interrupts */
	phy_write_paged(phydev, MARVELL_PAGE_PTP_PORT_1,
			PTP1_PORT_CONFIG_2, 0);

	return 0;
}

static void marvell_ptp_port_disable(struct phy_device *phydev)
{
	/* Disable PTP */
	phy_write_paged(phydev, MARVELL_PAGE_PTP_PORT_1,
			PTP1_PORT_CONFIG_0, PTP1_PORT_CONFIG_0_DISPTP);

	/* Disable interrupts */
	phy_write_paged(phydev, MARVELL_PAGE_PTP_PORT_1,
			PTP1_PORT_CONFIG_2, 0);
}

/* This function should be called from the PHY threaded interrupt
 * handler to process any stored timestamps in a timely manner.
 * The presence of an interrupt has an effect on how quickly a
 * timestamp requiring received packet will be processed.
 */
irqreturn_t marvell_ptp_irq(struct phy_device *phydev)
{
	struct marvell_ptp *ptp;
	irqreturn_t ret = IRQ_NONE;

	if (!phydev->mii_ts)
		return ret;

	ptp = mii_ts_to_ptp(phydev->mii_ts);
	if (marvell_ptp_rx_ts(ptp))
		ret = IRQ_HANDLED;

	if (ptp->tx_skb && marvell_ptp_txtstamp_complete(ptp))
		ret = IRQ_HANDLED;

	return ret;
}
EXPORT_SYMBOL_GPL(marvell_ptp_irq);

static void marvell_ptp_worker(struct work_struct *work)
{
	struct marvell_ptp *ptp = container_of(work, struct marvell_ptp,
					       ts_work.work);

	marvell_ptp_rx_ts(ptp);

	if (ptp->tx_skb)
		marvell_ptp_txtstamp_complete(ptp);

	marvell_ptp_rx_expire(ptp);

	if (!skb_queue_empty(&ptp->rx_queue) || ptp->tx_skb)
		schedule_delayed_work(&ptp->ts_work, 2);
}

int marvell_ptp_probe(struct phy_device *phydev)
{
	struct marvell_ptp *ptp;
	int err, i;

	ptp = devm_kzalloc(&phydev->mdio.dev, sizeof(*ptp), GFP_KERNEL);
	if (!ptp)
		return -ENOMEM;

	ptp->phydev = phydev;
	ptp->mii_ts.rxtstamp = marvell_ptp_rxtstamp;
	ptp->mii_ts.txtstamp = marvell_ptp_txtstamp;
	ptp->mii_ts.hwtstamp = marvell_ptp_hwtstamp;
	ptp->mii_ts.ts_info = marvell_ptp_ts_info;

	INIT_DELAYED_WORK(&ptp->ts_work, marvell_ptp_worker);
	mutex_init(&ptp->rx_mutex);
	INIT_LIST_HEAD(&ptp->rx_free);
	INIT_LIST_HEAD(&ptp->rx_pend);
	skb_queue_head_init(&ptp->rx_queue);

	for (i = 0; i < ARRAY_SIZE(ptp->rx_ts); i++)
		list_add_tail(&ptp->rx_ts[i].node, &ptp->rx_free);

	/* Get the TAI for this PHY. */
	err = marvell_tai_get(&ptp->tai, phydev);
	if (err)
		return err;

	/* Configure this PTP port */
	err = marvell_ptp_port_config(phydev);
	if (err) {
		marvell_tai_put(ptp->tai);
		return err;
	}

	phydev->mii_ts = &ptp->mii_ts;

	return 0;
}
EXPORT_SYMBOL_GPL(marvell_ptp_probe);

void marvell_ptp_remove(struct phy_device *phydev)
{
	struct marvell_ptp *ptp;

	if (!phydev->mii_ts)
		return;

	/* Disconnect from the net subsystem - we assume there is no
	 * packet activity at this point.
	 */
	ptp = mii_ts_to_ptp(phydev->mii_ts);
	phydev->mii_ts = NULL;

	cancel_delayed_work_sync(&ptp->ts_work);

	/* Free or dequeue all pending skbs */
	if (ptp->tx_skb)
		kfree_skb(ptp->tx_skb);

	skb_queue_purge(&ptp->rx_queue);

	/* Ensure that the port is disabled */
	marvell_ptp_port_disable(phydev);
	marvell_tai_put(ptp->tai);
}
EXPORT_SYMBOL_GPL(marvell_ptp_remove);

MODULE_AUTHOR("Russell King");
MODULE_DESCRIPTION("Marvell PHY PTP library");
MODULE_LICENSE("GPL v2");
