// SPDX-License-Identifier: GPL-2.0-only

#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>

#include "netlink.h"
#include "common.h"
#include "bitset.h"
#include "../core/dev.h"

struct hwtst_provider {
	int index;
	u32 qualifier;
};

struct tsinfo_req_info {
	struct ethnl_req_info		base;
	struct hwtst_provider		hwtst;
	bool				get_hwtstamp;
};

struct tsinfo_reply_data {
	struct ethnl_reply_data		base;
	union {
		struct kernel_ethtool_ts_info		ts_info;
		struct {
			u32 tx_type;
			u32 rx_filter;
			u32 flags;
		} hwtst_config;
	};
};

#define TSINFO_REQINFO(__req_base) \
	container_of(__req_base, struct tsinfo_req_info, base)

#define TSINFO_REPDATA(__reply_base) \
	container_of(__reply_base, struct tsinfo_reply_data, base)

const struct nla_policy
ethnl_tsinfo_hwtstamp_provider_policy[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_MAX + 1] = {
	[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_INDEX] =
		NLA_POLICY_MIN(NLA_S32, 0),
	[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_QUALIFIER] =
		NLA_POLICY_MAX(NLA_U32, HWTSTAMP_PROVIDER_QUALIFIER_CNT - 1)
};

const struct nla_policy ethnl_tsinfo_get_policy[ETHTOOL_A_TSINFO_MAX + 1] = {
	[ETHTOOL_A_TSINFO_HEADER]		=
		NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_TSINFO_GHWTSTAMP] =
		NLA_POLICY_MAX(NLA_U8, 1),
	[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST] =
		NLA_POLICY_NESTED(ethnl_tsinfo_hwtstamp_provider_policy),
};

static int tsinfo_parse_hwtstamp_provider(const struct nlattr *nest,
					  struct hwtst_provider *hwtst,
					  struct netlink_ext_ack *extack,
					  bool *mod)
{
	struct nlattr *tb[ARRAY_SIZE(ethnl_tsinfo_hwtstamp_provider_policy)];
	int ret;

	ret = nla_parse_nested(tb,
			       ARRAY_SIZE(ethnl_tsinfo_hwtstamp_provider_policy) - 1,
			       nest,
			       ethnl_tsinfo_hwtstamp_provider_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, nest, tb, ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_INDEX) ||
	    NL_REQ_ATTR_CHECK(extack, nest, tb, ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_QUALIFIER))
		return -EINVAL;

	hwtst->index = nla_get_u32(tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_INDEX]);
	hwtst->qualifier = nla_get_u32(tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_QUALIFIER]);

	ethnl_update_u32(&hwtst->index,
			 tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_INDEX],
			 mod);
	ethnl_update_u32(&hwtst->qualifier,
			 tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_QUALIFIER],
			 mod);

	return 0;
}

static int
tsinfo_parse_request(struct ethnl_req_info *req_base, struct nlattr **tb,
		     struct netlink_ext_ack *extack)
{
	struct tsinfo_req_info *req = TSINFO_REQINFO(req_base);
	bool mod = false;

	req->hwtst.index = -1;

	if (tb[ETHTOOL_A_TSINFO_GHWTSTAMP]) {
		req->get_hwtstamp = nla_get_u8(tb[ETHTOOL_A_TSINFO_GHWTSTAMP]);

		/* We support only the get of the current hwtstamp config
		 * for now.
		 */
		if (req->get_hwtstamp &&
		    tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST]) {
			NL_SET_ERR_MSG_ATTR(extack,
					    tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
					    "only getting the current hwtstamp configuration is supported");
			return -EOPNOTSUPP;
		}
	}

	if (!tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST])
		return 0;

	return tsinfo_parse_hwtstamp_provider(tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
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

	if (req->get_hwtstamp) {
		struct kernel_hwtstamp_config cfg = {};

		if (!dev->netdev_ops->ndo_hwtstamp_get) {
			ret = -EOPNOTSUPP;
			goto out;
		}

		ret = dev_get_hwtstamp_phylib(dev, &cfg);
		data->hwtst_config.tx_type = BIT(cfg.tx_type);
		data->hwtst_config.rx_filter = BIT(cfg.rx_filter);
		data->hwtst_config.flags = BIT(cfg.flags);
	} else if (req->hwtst.index != -1) {
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

static int
tsinfo_reply_size_hwtstamp_config(const struct tsinfo_reply_data *data,
				  bool compact)
{
	int len = 0;
	int ret;

	if (data->hwtst_config.flags)
		len += nla_total_size(sizeof(u32));

	if (data->hwtst_config.tx_type) {
		ret = ethnl_bitset32_size(&data->hwtst_config.tx_type,
					  NULL, __HWTSTAMP_TX_CNT,
					  ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSINFO_TX_TYPES */
	}
	if (data->hwtst_config.rx_filter) {
		ret = ethnl_bitset32_size(&data->hwtst_config.rx_filter,
					  NULL, __HWTSTAMP_FILTER_CNT,
					  ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSINFO_RX_FILTERS */
	}

	return len;
}

static int
tsinfo_reply_size_ts_info(const struct kernel_ethtool_ts_info *ts_info,
			  bool compact)
{
	int len = 0;
	int ret;

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
		/* _TSINFO_HWTSTAMP_PROVIDER_NEST */
		len += 2 * nla_total_size(sizeof(u32));
		len += nla_total_size(sizeof(u32));	/* _TSINFO_PHC_INDEX */
	}

	return len;
}

static int tsinfo_reply_size(const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	const struct tsinfo_reply_data *data = TSINFO_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	struct tsinfo_req_info *req = TSINFO_REQINFO(req_base);

	BUILD_BUG_ON(__SOF_TIMESTAMPING_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_TX_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_FILTER_CNT > 32);

	if (req->get_hwtstamp)
		return tsinfo_reply_size_hwtstamp_config(data, compact);

	return tsinfo_reply_size_ts_info(&data->ts_info, compact);
}

static int tsinfo_fill_ts_info(struct sk_buff *skb,
			       const struct kernel_ethtool_ts_info *ts_info,
			       bool compact)
{
	struct nlattr *nest;
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
		ret = nla_put_u32(skb, ETHTOOL_A_TSINFO_PHC_INDEX,
				  ts_info->phc_index);
		if (ret)
			return -EMSGSIZE;

		nest = nla_nest_start(skb, ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST);
		if (!nest)
			return -EMSGSIZE;

		if (nla_put_u32(skb, ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_INDEX,
				ts_info->phc_index) ||
		    nla_put_u32(skb,
				ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_QUALIFIER,
				ts_info->phc_qualifier)) {
			nla_nest_cancel(skb, nest);
			return -EMSGSIZE;
		}

		nla_nest_end(skb, nest);
	}
	return 0;
}

static int
tsinfo_fill_hwtstamp_config(struct sk_buff *skb,
			    const struct tsinfo_reply_data *data,
			    bool compact)
{
	int ret;

	if (data->hwtst_config.flags) {
		ret = nla_put_u32(skb, ETHTOOL_A_TSINFO_HWTSTAMP_FLAGS,
				  data->hwtst_config.flags);
		if (ret < 0)
			return ret;
	}

	if (data->hwtst_config.tx_type) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSINFO_TX_TYPES,
					 &data->hwtst_config.tx_type, NULL,
					 __HWTSTAMP_TX_CNT,
					 ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
	}

	if (data->hwtst_config.rx_filter) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSINFO_RX_FILTERS,
					 &data->hwtst_config.rx_filter,
					 NULL, __HWTSTAMP_FILTER_CNT,
					 ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
	}
	return 0;
}

static int tsinfo_fill_reply(struct sk_buff *skb,
			     const struct ethnl_req_info *req_base,
			     const struct ethnl_reply_data *reply_base)
{
	const struct tsinfo_reply_data *data = TSINFO_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	struct tsinfo_req_info *req = TSINFO_REQINFO(req_base);

	if (req->get_hwtstamp)
		return tsinfo_fill_hwtstamp_config(skb, data, compact);

	return tsinfo_fill_ts_info(skb, &data->ts_info, compact);
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
	void *ehdr;
	int ret;

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
	if (ret < 0)
		genlmsg_cancel(skb, ehdr);
	else
		genlmsg_end(skb, ehdr);
	return ret;
}

static int ethnl_tsinfo_dump_one_dev(struct sk_buff *skb, struct net_device *dev,
				     struct netlink_callback *cb)
{
	struct ethnl_tsinfo_dump_ctx *ctx = (void *)cb->ctx;
	struct ptp_clock *ptp;
	int ret;

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

	if (ret == -EMSGSIZE && skb->len)
		return skb->len;
	return ret;
}

static int
tsinfo_dump_parse_request(struct nlattr **tb, struct netlink_ext_ack *extack)
{
	if (tb[ETHTOOL_A_TSINFO_GHWTSTAMP] &&
	    nla_get_u8(tb[ETHTOOL_A_TSINFO_GHWTSTAMP])) {
		/* We do not support simultaneous hwtstamp for now */
		NL_SET_ERR_MSG_ATTR(extack,
				    tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
				    "only getting the current hwtstamp configuration is supported");
		return -EOPNOTSUPP;
	}

	return 0;
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

	ret = tsinfo_dump_parse_request(tb, cb->extack);
	if (ret < 0)
		goto put_header_dev;

	ctx->req_info = req_info;
	ctx->reply_data = reply_data;
	ctx->pos_ifindex = 0;
	ctx->pos_phcindex = 0;
	ctx->pos_phcqualifier = HWTSTAMP_PROVIDER_QUALIFIER_PRECISE;

	return 0;

put_header_dev:
	if (req_info->base.dev) {
		ethnl_parse_header_dev_put(&req_info->base);
		req_info->base.dev = NULL;
	}
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

/* TSINFO_SET (set hwtstamp config) */
const struct nla_policy ethnl_tsinfo_set_policy[ETHTOOL_A_TSINFO_MAX + 1] = {
	[ETHTOOL_A_TSINFO_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST] = { .type = NLA_NESTED },
	[ETHTOOL_A_TSINFO_HWTSTAMP_FLAGS] = { .type = NLA_U32 },
	[ETHTOOL_A_TSINFO_RX_FILTERS] = { .type = NLA_NESTED },
	[ETHTOOL_A_TSINFO_TX_TYPES] = { .type = NLA_NESTED },
};

static int ethnl_set_tsinfo_validate(struct ethnl_req_info *req_base,
				     struct genl_info *info)
{
	const struct net_device_ops *ops = req_base->dev->netdev_ops;

	if (!ops->ndo_hwtstamp_set || !ops->ndo_hwtstamp_get)
		return -EOPNOTSUPP;

	return 1;
}

static int ethnl_set_tsinfo(struct ethnl_req_info *req_base,
			    struct genl_info *info)
{
	unsigned long mask = 0, req_rx_filter, req_tx_type;
	struct kernel_hwtstamp_config hwtst_config = {0};
	struct hwtstamp_provider hwtstamp = {0};
	struct net_device *dev = req_base->dev;
	struct nlattr **tb = info->attrs;
	bool mod = false;
	int ret;

	BUILD_BUG_ON(__HWTSTAMP_TX_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_FILTER_CNT > 32);

	if (!netif_device_present(dev))
		return -ENODEV;

	if (tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST]) {
		struct hwtst_provider hwtst;

		if (dev->hwtstamp.ptp) {
			hwtst.index = ptp_clock_index(dev->hwtstamp.ptp);
			hwtst.qualifier = dev->hwtstamp.qualifier;
		}

		ret = tsinfo_parse_hwtstamp_provider(tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
						     &hwtst, info->extack, &mod);
		if (ret < 0)
			return ret;

		/* Does the hwtstamp supported in the netdev topology */
		if (mod) {
			hwtstamp.ptp = ptp_clock_get_by_index(&dev->dev, hwtst.index);
			hwtstamp.qualifier = hwtst.qualifier;
			if (!hwtstamp.ptp) {
				NL_SET_ERR_MSG_ATTR(info->extack,
						    tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
						    "no phc at such index");
				return -ENODEV;
			}

			if (!netdev_support_hwtstamp(dev, &hwtstamp)) {
				NL_SET_ERR_MSG_ATTR(info->extack,
						    tb[ETHTOOL_A_TSINFO_HWTSTAMP_PROVIDER_NEST],
						    "phc not in this net device topology");
				ret = -ENODEV;
				goto err;
			}
		}
	}

	/* Get current hwtstamp config if we are not changing the hwtstamp
	 * source
	 */
	if (!mod) {
		ret = dev_get_hwtstamp_phylib(dev, &hwtst_config);
		if (ret < 0 && ret != EOPNOTSUPP)
			goto err;
	}

	/* Get the hwtstamp config from netlink */
	if (tb[ETHTOOL_A_TSINFO_TX_TYPES]) {
		ret = ethnl_parse_bitset(&req_tx_type, &mask,
					 __HWTSTAMP_TX_CNT,
					 tb[ETHTOOL_A_TSINFO_TX_TYPES],
					 ts_tx_type_names, info->extack);
		if (ret < 0)
			goto err;

		/* Select only one tx type at a time */
		if (ffs(req_tx_type) != fls(req_tx_type)) {
			ret = -EINVAL;
			goto err;
		}

		hwtst_config.tx_type = ffs(req_tx_type) - 1;
	}
	if (tb[ETHTOOL_A_TSINFO_RX_FILTERS]) {
		ret = ethnl_parse_bitset(&req_rx_filter, &mask,
					 __HWTSTAMP_FILTER_CNT,
					 tb[ETHTOOL_A_TSINFO_RX_FILTERS],
					 ts_rx_filter_names, info->extack);
		if (ret < 0)
			goto err;

		/* Select only one rx filter at a time */
		if (ffs(req_rx_filter) != fls(req_rx_filter)) {
			ret = -EINVAL;
			goto err;
		}

		hwtst_config.rx_filter = ffs(req_rx_filter) - 1;
	}
	if (tb[ETHTOOL_A_TSINFO_HWTSTAMP_FLAGS]) {
		ret = nla_get_u32(tb[ETHTOOL_A_TSINFO_HWTSTAMP_FLAGS]);
		if (ret < 0)
			goto err;
		hwtst_config.flags = ret;
	}

	ret = net_hwtstamp_validate(&hwtst_config);
	if (ret)
		goto err;

	/* Disable current time stamping if we try to enable another one */
	if (mod && (hwtst_config.tx_type || hwtst_config.rx_filter)) {
		struct kernel_hwtstamp_config zero_config = {0};

		ret = dev_set_hwtstamp_phylib(dev, &zero_config, info->extack);
		if (ret < 0)
			goto err;
	}

	/* Changed the selected hwtstamp source if needed */
	if (mod) {
		ptp_clock_put(&dev->dev, dev->hwtstamp.ptp);
		memcpy(&dev->hwtstamp, &hwtstamp, sizeof(hwtstamp));
	}

	ret = dev_set_hwtstamp_phylib(dev, &hwtst_config, info->extack);
	if (ret < 0)
		goto err;

	return 1;

err:
	if (hwtstamp.ptp)
		ptp_clock_put(&dev->dev, hwtstamp.ptp);

	return ret;
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

	.set_validate		= ethnl_set_tsinfo_validate,
	.set			= ethnl_set_tsinfo,
};
