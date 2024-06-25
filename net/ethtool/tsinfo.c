// SPDX-License-Identifier: GPL-2.0-only

#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>

#include "netlink.h"
#include "common.h"
#include "bitset.h"
#include "ts.h"

struct tsinfo_req_info {
	struct ethnl_req_info		base;
	struct hwtst_provider		hwtst;
};

struct tsinfo_reply_data {
	struct ethnl_reply_data		base;
	struct kernel_ethtool_ts_info	ts_info;
	struct ethtool_ts_stats		stats;
};

#define TSINFO_REQINFO(__req_base) \
	container_of(__req_base, struct tsinfo_req_info, base)

#define TSINFO_REPDATA(__reply_base) \
	container_of(__reply_base, struct tsinfo_reply_data, base)

#define ETHTOOL_TS_STAT_CNT \
	(__ETHTOOL_A_TS_STAT_CNT - (ETHTOOL_A_TS_STAT_UNSPEC + 1))

const struct nla_policy ethnl_tsinfo_get_policy[ETHTOOL_A_TSINFO_MAX + 1] = {
	[ETHTOOL_A_TSINFO_HEADER]		=
		NLA_POLICY_NESTED(ethnl_header_policy_stats),
	[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER] =
		NLA_POLICY_NESTED(ethnl_ts_hwtst_prov_policy),
};

static int
tsinfo_parse_request(struct ethnl_req_info *req_base, struct nlattr **tb,
		     struct netlink_ext_ack *extack)
{
	struct tsinfo_req_info *req = TSINFO_REQINFO(req_base);
	bool mod = false;

	req->hwtst.index = -1;

	if (!tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER])
		return 0;

	return ts_parse_hwtst_provider(tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER],
				       &req->hwtst, extack, &mod);
}

static int tsinfo_prepare_data(const struct ethnl_req_info *req_base,
			       struct ethnl_reply_data *reply_base,
			       const struct genl_info *info)
{
	struct tsinfo_reply_data *data = TSINFO_REPDATA(reply_base);
	struct tsinfo_req_info *req = TSINFO_REQINFO(req_base);
	struct net_device *dev = reply_base->dev;
	int ret;

	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;

	if (req_base->flags & ETHTOOL_FLAG_STATS) {
		ethtool_stats_init((u64 *)&data->stats,
				   sizeof(data->stats) / sizeof(u64));
		if (dev->ethtool_ops->get_ts_stats)
			dev->ethtool_ops->get_ts_stats(dev, &data->stats);
	}

	if (req->hwtst.index != -1) {
		struct hwtstamp_provider hwtstamp;

		hwtstamp.ptp = ptp_clock_get_by_index(&dev->dev, req->hwtst.index);
		if (!hwtstamp.ptp) {
			ret = -ENODEV;
			goto out;
		}
		hwtstamp.qualifier = req->hwtst.qualifier;

		ret = ethtool_get_ts_info_by_phc(dev, &data->ts_info,
						 &hwtstamp);
		ptp_clock_put(&dev->dev, hwtstamp.ptp);
	} else {
		ret = __ethtool_get_ts_info(dev, &data->ts_info);
	}

out:
	ethnl_ops_complete(dev);

	return ret;
}

static int tsinfo_reply_size(const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	const struct tsinfo_reply_data *data = TSINFO_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct kernel_ethtool_ts_info *ts_info = &data->ts_info;
	int len = 0;
	int ret;

	BUILD_BUG_ON(__SOF_TIMESTAMPING_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_TX_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_FILTER_CNT > 32);

	if (ts_info->so_timestamping) {
		ret = ethnl_bitset32_size(&ts_info->so_timestamping, NULL,
					  __SOF_TIMESTAMPING_CNT,
					  sof_timestamping_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSINFO_TIMESTAMPING */
	}
	if (ts_info->tx_types) {
		ret = ethnl_bitset32_size(&ts_info->tx_types, NULL,
					  __HWTSTAMP_TX_CNT,
					  ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSINFO_TX_TYPES */
	}
	if (ts_info->rx_filters) {
		ret = ethnl_bitset32_size(&ts_info->rx_filters, NULL,
					  __HWTSTAMP_FILTER_CNT,
					  ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSINFO_RX_FILTERS */
	}
	if (ts_info->phc_index >= 0) {
		/* _TSINFO_HWTSTAMP_PROVIDER */
		len += 2 * nla_total_size(sizeof(u32));
		len += nla_total_size(sizeof(u32));	/* _TSINFO_PHC_INDEX */
	}
	if (req_base->flags & ETHTOOL_FLAG_STATS)
		len += nla_total_size(0) + /* _TSINFO_STATS */
		       nla_total_size_64bit(sizeof(u64)) * ETHTOOL_TS_STAT_CNT;

	return len;
}

static int tsinfo_put_stat(struct sk_buff *skb, u64 val, u16 attrtype)
{
	if (val == ETHTOOL_STAT_NOT_SET)
		return 0;
	if (nla_put_uint(skb, attrtype, val))
		return -EMSGSIZE;
	return 0;
}

static int tsinfo_put_stats(struct sk_buff *skb,
			    const struct ethtool_ts_stats *stats)
{
	struct nlattr *nest;

	nest = nla_nest_start(skb, ETHTOOL_A_TSINFO_STATS);
	if (!nest)
		return -EMSGSIZE;

	if (tsinfo_put_stat(skb, stats->tx_stats.pkts,
			    ETHTOOL_A_TS_STAT_TX_PKTS) ||
	    tsinfo_put_stat(skb, stats->tx_stats.lost,
			    ETHTOOL_A_TS_STAT_TX_LOST) ||
	    tsinfo_put_stat(skb, stats->tx_stats.err,
			    ETHTOOL_A_TS_STAT_TX_ERR))
		goto err_cancel;

	nla_nest_end(skb, nest);
	return 0;

err_cancel:
	nla_nest_cancel(skb, nest);
	return -EMSGSIZE;
}

static int tsinfo_fill_reply(struct sk_buff *skb,
			     const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	const struct tsinfo_reply_data *data = TSINFO_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	const struct kernel_ethtool_ts_info *ts_info = &data->ts_info;
	int ret;

	if (ts_info->so_timestamping) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSINFO_TIMESTAMPING,
					 &ts_info->so_timestamping, NULL,
					 __SOF_TIMESTAMPING_CNT,
					 sof_timestamping_names, compact);
		if (ret < 0)
			return ret;
	}
	if (ts_info->tx_types) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSINFO_TX_TYPES,
					 &ts_info->tx_types, NULL,
					 __HWTSTAMP_TX_CNT,
					 ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
	}
	if (ts_info->rx_filters) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSINFO_RX_FILTERS,
					 &ts_info->rx_filters, NULL,
					 __HWTSTAMP_FILTER_CNT,
					 ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
	}
	if (ts_info->phc_index >= 0) {
		struct nlattr *nest;

		ret = nla_put_u32(skb, ETHTOOL_A_TSINFO_PHC_INDEX,
				  ts_info->phc_index);
		if (ret)
			return -EMSGSIZE;

		nest = nla_nest_start(skb, ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER);
		if (!nest)
			return -EMSGSIZE;

		if (nla_put_u32(skb, ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,
				ts_info->phc_index) ||
		    nla_put_u32(skb,
				ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,
				ts_info->phc_qualifier)) {
			nla_nest_cancel(skb, nest);
			return -EMSGSIZE;
		}

		nla_nest_end(skb, nest);
	}
	if (req_base->flags & ETHTOOL_FLAG_STATS &&
	    tsinfo_put_stats(skb, &data->stats))
		return -EMSGSIZE;

	return 0;
}

struct ethnl_tsinfo_dump_ctx {
	struct tsinfo_req_info		*req_info;
	struct tsinfo_reply_data	*reply_data;
	unsigned long			pos_ifindex;
	unsigned long			pos_phcindex;
	enum hwtstamp_provider_qualifier pos_phcqualifier;
};

static int ethnl_tsinfo_dump_one_ptp(struct sk_buff *skb, struct net_device *dev,
				     struct netlink_callback *cb,
				     struct ptp_clock *ptp)
{
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct tsinfo_reply_data *reply_data;
	struct tsinfo_req_info *req_info;
	void *ehdr = NULL;
	int ret = 0;

	reply_data = ctx->reply_data;
	req_info = ctx->req_info;
	req_info->hwtst.index = ptp_clock_index(ptp);

	for (; ctx->pos_phcqualifier < HWTSTAMP_PROVIDER_QUALIFIER_CNT;
	     ctx->pos_phcqualifier++) {
		if (!netdev_support_hwtstamp_qualifier(dev,
						       ctx->pos_phcqualifier))
			continue;

		ehdr = ethnl_dump_put(skb, cb,
				      ETHTOOL_MSG_TSINFO_GET_REPLY);
		if (!ehdr)
			return -EMSGSIZE;

		memset(reply_data, 0, sizeof(*reply_data));
		reply_data->base.dev = dev;
		req_info->hwtst.qualifier = ctx->pos_phcqualifier;
		ret = tsinfo_prepare_data(&req_info->base,
					  &reply_data->base,
					  genl_info_dump(cb));
		if (ret < 0)
			break;

		ret = ethnl_fill_reply_header(skb, dev,
					      ETHTOOL_A_TSINFO_HEADER);
		if (ret < 0)
			break;

		ret = tsinfo_fill_reply(skb, &req_info->base,
					&reply_data->base);
		if (ret < 0)
			break;
	}

	reply_data->base.dev = NULL;
	if (!ret && ehdr)
		genlmsg_end(skb, ehdr);
	else
		genlmsg_cancel(skb, ehdr);
	return ret;
}

static int ethnl_tsinfo_dump_one_dev(struct sk_buff *skb, struct net_device *dev,
				     struct netlink_callback *cb)
{
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct ptp_clock *ptp;
	int ret = 0;

	netdev_for_each_ptp_clock_start(dev, ctx->pos_phcindex, ptp,
					ctx->pos_phcindex) {
		ret = ethnl_tsinfo_dump_one_ptp(skb, dev, cb, ptp);
		if (ret < 0 && ret != -EOPNOTSUPP)
			break;
		ctx->pos_phcqualifier = HWTSTAMP_PROVIDER_QUALIFIER_PRECISE;
	}

	return ret;
}

int ethnl_tsinfo_dumpit(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct net *net = sock_net(skb->sk);
	struct net_device *dev;
	int ret = 0;

	rtnl_lock();
	if (ctx->req_info->base.dev) {
		ret = ethnl_tsinfo_dump_one_dev(skb,
						ctx->req_info->base.dev,
						cb);
	} else {
		for_each_netdev_dump(net, dev, ctx->pos_ifindex) {
			ret = ethnl_tsinfo_dump_one_dev(skb, dev, cb);
			if (ret < 0 && ret != -EOPNOTSUPP)
				break;
			ctx->pos_phcindex = 0;
		}
	}
	rtnl_unlock();

	return ret;
}

int ethnl_tsinfo_start(struct netlink_callback *cb)
{
	const struct genl_dumpit_info *info = genl_dumpit_info(cb);
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct nlattr **tb = info->info.attrs;
	struct tsinfo_reply_data *reply_data;
	struct tsinfo_req_info *req_info;
	int ret;

	BUILD_BUG_ON(sizeof(*ctx) > sizeof(cb->ctx));

	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (!req_info)
		return -ENOMEM;
	reply_data = kzalloc(sizeof(*reply_data), GFP_KERNEL);
	if (!reply_data) {
		ret = -ENOMEM;
		goto free_req_info;
	}

	ret = ethnl_parse_header_dev_get(&req_info->base,
					 tb[ETHTOOL_A_TSINFO_HEADER],
					 sock_net(cb->skb->sk), cb->extack,
					 false);
	if (ret < 0)
		goto free_reply_data;

	ctx->req_info = req_info;
	ctx->reply_data = reply_data;
	ctx->pos_ifindex = 0;
	ctx->pos_phcindex = 0;
	ctx->pos_phcqualifier = HWTSTAMP_PROVIDER_QUALIFIER_PRECISE;

	return 0;

free_reply_data:
	kfree(reply_data);
free_req_info:
	kfree(req_info);

	return ret;
}

int ethnl_tsinfo_done(struct netlink_callback *cb)
{
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct tsinfo_req_info *req_info = ctx->req_info;

	ethnl_parse_header_dev_put(&req_info->base);
	kfree(ctx->reply_data);
	kfree(ctx->req_info);

	return 0;
}

const struct ethnl_request_ops ethnl_tsinfo_request_ops = {
	.request_cmd		= ETHTOOL_MSG_TSINFO_GET,
	.reply_cmd		= ETHTOOL_MSG_TSINFO_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_TSINFO_HEADER,
	.req_info_size		= sizeof(struct tsinfo_req_info),
	.reply_data_size	= sizeof(struct tsinfo_reply_data),

	.parse_request		= tsinfo_parse_request,
	.prepare_data		= tsinfo_prepare_data,
	.reply_size		= tsinfo_reply_size,
	.fill_reply		= tsinfo_fill_reply,
};
