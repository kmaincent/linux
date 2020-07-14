// SPDX-License-Identifier: GPL-2.0+
/*
 * Marvell PTP driver for 88E1510, 88E1512, 88E1514 and 88E1518 PHYs
 *
 * This file implements TAI support as a PTP clock. Timecounter/cyclecounter
 * representation taken from Marvell 88E6xxx DSA driver. We may need to share
 * the TAI between multiple PHYs in a multiport PHY.
 */
#include <linux/ktime.h>
#include <linux/slab.h>
#include <linux/phy.h>
#include "marvell_tai.h"

#define MARVELL_PAGE_MISC			6
#define GCR					20
#define GCR_PTP_POWER_DOWN			BIT(9)
#define GCR_PTP_REF_CLOCK_SOURCE		BIT(8)
#define GCR_PTP_INPUT_SOURCE			BIT(7)
#define GCR_PTP_OUTPUT				BIT(6)

#define MARVELL_PAGE_TAI_GLOBAL			12
#define TAI_CONFIG_0				0
#define TAI_CONFIG_0_EVENTCAPOV			BIT(15)
#define TAI_CONFIG_0_TRIGGENINTEN		BIT(9)
#define TAI_CONFIG_0_EVENTCAPINTEN		BIT(8)

#define TAI_CONFIG_9				9
#define TAI_CONFIG_9_EVENTERR			BIT(9)
#define TAI_CONFIG_9_EVENTCAPVALID		BIT(8)

#define TAI_EVENT_CAPTURE_TIME_LO		10
#define TAI_EVENT_CAPTURE_TIME_HI		11

#define MARVELL_PAGE_PTP_GLOBAL			14
#define PTPG_CONFIG_0				0
#define PTPG_CONFIG_1				1
#define PTPG_CONFIG_2				2
#define PTPG_CONFIG_3				3
#define PTPG_CONFIG_3_TSATSFD			BIT(0)
#define PTPG_STATUS				8
#define PTPG_READPLUS_COMMAND			14
#define PTPG_READPLUS_DATA			15

static DEFINE_SPINLOCK(tai_list_lock);
static LIST_HEAD(tai_list);

static struct marvell_tai *cc_to_tai(const struct cyclecounter *cc)
{
	return container_of(cc, struct marvell_tai, cyclecounter);
}

/* Read the global time registers using the readplus command */
static u64 marvell_tai_clock_read(const struct cyclecounter *cc)
{
	struct marvell_tai *tai = cc_to_tai(cc);
	struct phy_device *phydev = tai->phydev;
	int err, oldpage, lo, hi;

	oldpage = phy_select_page(phydev, MARVELL_PAGE_PTP_GLOBAL);
	if (oldpage >= 0) {
		/* 88e151x says to write 0x8e0e */
		ptp_read_system_prets(tai->sts);
		err = __phy_write(phydev, PTPG_READPLUS_COMMAND, 0x8e0e);
		ptp_read_system_postts(tai->sts);
		lo = __phy_read(phydev, PTPG_READPLUS_DATA);
		hi = __phy_read(phydev, PTPG_READPLUS_DATA);
	}
	err = phy_restore_page(phydev, oldpage, err);

	if (err || lo < 0 || hi < 0)
		return 0;

	return lo | hi << 16;
}

u64 marvell_tai_cyc2time(struct marvell_tai *tai, u32 cyc)
{
	u64 ns;

	mutex_lock(&tai->mutex);
	ns = timecounter_cyc2time(&tai->timecounter, cyc);
	mutex_unlock(&tai->mutex);

	return ns;
}

static struct marvell_tai *ptp_to_tai(struct ptp_clock_info *ptp)
{
	return container_of(ptp, struct marvell_tai, caps);
}

static int marvell_tai_adjfine(struct ptp_clock_info *ptp, long scaled_ppm)
{
	struct marvell_tai *tai = ptp_to_tai(ptp);
	bool neg;
	u32 diff;
	u64 adj;

	neg = scaled_ppm < 0;
	if (neg)
		scaled_ppm = -scaled_ppm;

	adj = tai->cc_mult_num;
	adj *= scaled_ppm;
	diff = div_u64(adj, tai->cc_mult_den);

	mutex_lock(&tai->mutex);
	timecounter_read(&tai->timecounter);
	tai->cyclecounter.mult = neg ? tai->cc_mult - diff :
				       tai->cc_mult + diff;
	mutex_unlock(&tai->mutex);

	return 0;
}

static int marvell_tai_adjtime(struct ptp_clock_info *ptp, s64 delta)
{
	struct marvell_tai *tai = ptp_to_tai(ptp);

	mutex_lock(&tai->mutex);
	timecounter_adjtime(&tai->timecounter, delta);
	mutex_unlock(&tai->mutex);

	return 0;
}

static int marvell_tai_gettimex64(struct ptp_clock_info *ptp,
				  struct timespec64 *ts,
				  struct ptp_system_timestamp *sts)
{
	struct marvell_tai *tai = ptp_to_tai(ptp);
	u64 ns;

	mutex_lock(&tai->mutex);
	tai->sts = sts;
	ns = timecounter_read(&tai->timecounter);
	tai->sts = NULL;
	mutex_unlock(&tai->mutex);

	*ts = ns_to_timespec64(ns);

	return 0;
}

static int marvell_tai_settime64(struct ptp_clock_info *ptp,
				 const struct timespec64 *ts)
{
	struct marvell_tai *tai = ptp_to_tai(ptp);
	u64 ns = timespec64_to_ns(ts);

	mutex_lock(&tai->mutex);
	timecounter_init(&tai->timecounter, &tai->cyclecounter, ns);
	mutex_unlock(&tai->mutex);

	return 0;
}

/* Periodically read the timecounter to keep the time refreshed. */
static long marvell_tai_aux_work(struct ptp_clock_info *ptp)
{
	struct marvell_tai *tai = ptp_to_tai(ptp);

	mutex_lock(&tai->mutex);
	timecounter_read(&tai->timecounter);
	mutex_unlock(&tai->mutex);

	return tai->half_overflow_period;
}

/* Configure the global (shared between ports) configuration for the PHY. */
static int marvell_tai_global_config(struct phy_device *phydev)
{
	int err;

	/* Power up PTP */
	err = phy_modify_paged(phydev, MARVELL_PAGE_MISC, GCR,
			       GCR_PTP_POWER_DOWN, 0);
	if (err)
		return err;

	/* Set ether-type for IEEE1588 packets */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_GLOBAL,
			      PTPG_CONFIG_0, ETH_P_1588);
	if (err < 0)
		return err;

	/* MsdIDTSEn - Enable timestamping on all PTP MessageIDs */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_GLOBAL,
			      PTPG_CONFIG_1, ~0);
	if (err < 0)
		return err;

	/* TSArrPtr - Point to Arr0 registers */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_GLOBAL,
			      PTPG_CONFIG_2, 0);
	if (err < 0)
		return err;

	/* TSAtSFD - timestamp at SFD */
	err = phy_write_paged(phydev, MARVELL_PAGE_PTP_GLOBAL,
			      PTPG_CONFIG_3, PTPG_CONFIG_3_TSATSFD);
	if (err < 0)
		return err;

	return 0;
}

int marvell_tai_get(struct marvell_tai **taip, struct phy_device *phydev)
{
	struct marvell_tai *tai;
	unsigned long overflow_ms;
	int err;

	err = marvell_tai_global_config(phydev);
	if (err < 0)
		return err;

	tai = kzalloc(sizeof(*tai), GFP_KERNEL);
	if (!tai)
		return -ENOMEM;

	mutex_init(&tai->mutex);

	tai->phydev = phydev;

	/* This assumes a 125MHz clock */
	tai->cc_mult = 8 << 28;
	tai->cc_mult_num = 1 << 9;
	tai->cc_mult_den = 15625U;

	tai->cyclecounter.read = marvell_tai_clock_read;
	tai->cyclecounter.mask = CYCLECOUNTER_MASK(32);
	tai->cyclecounter.mult = tai->cc_mult;
	tai->cyclecounter.shift = 28;

	overflow_ms = (1ULL << 32 * tai->cc_mult * 1000) >>
			tai->cyclecounter.shift;
	tai->half_overflow_period = msecs_to_jiffies(overflow_ms / 2);

	timecounter_init(&tai->timecounter, &tai->cyclecounter,
			 ktime_to_ns(ktime_get_real()));

	tai->caps.owner = THIS_MODULE;
	snprintf(tai->caps.name, sizeof(tai->caps.name), "Marvell PHY");
	/* max_adj of 1000000 is what MV88E6xxx DSA uses */
	tai->caps.max_adj = 1000000;
	tai->caps.adjfine = marvell_tai_adjfine;
	tai->caps.adjtime = marvell_tai_adjtime;
	tai->caps.gettimex64 = marvell_tai_gettimex64;
	tai->caps.settime64 = marvell_tai_settime64;
	tai->caps.do_aux_work = marvell_tai_aux_work;

	tai->ptp_clock = ptp_clock_register(&tai->caps, &phydev->mdio.dev);
	if (IS_ERR(tai->ptp_clock)) {
		kfree(tai);
		return PTR_ERR(tai->ptp_clock);
	}

	ptp_schedule_worker(tai->ptp_clock, tai->half_overflow_period);

	spin_lock(&tai_list_lock);
	list_add_tail(&tai->tai_node, &tai_list);
	spin_unlock(&tai_list_lock);

	*taip = tai;

	return 0;
}

void marvell_tai_put(struct marvell_tai *tai)
{
	ptp_clock_unregister(tai->ptp_clock);

	spin_lock(&tai_list_lock);
	list_del(&tai->tai_node);
	spin_unlock(&tai_list_lock);

	kfree(tai);
}
