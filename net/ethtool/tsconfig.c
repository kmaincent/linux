// SPDX-License-Identifier: GPL-2.0-only

#include <linux/net_tstamp.h>
#include <linux/ptp_clock_kernel.h>

#include "netlink.h"
#include "common.h"
#include "bitset.h"
#include "../core/dev.h"
#include "ts.h"

struct tsconfig_req_info {
	struct ethnl_req_info base;
};

struct tsconfig_reply_data {
	struct ethnl_reply_data		base;
	struct hwtst_provider		hwtst;
	struct {
		u32 tx_type;
		u32 rx_filter;
		u32 flags;
	} hwtst_config;
};

#define TSCONFIG_REPDATA(__reply_base) \
	container_of(__reply_base, struct tsconfig_reply_data, base)

const struct nla_policy ethnl_tsconfig_get_policy[ETHTOOL_A_TSCONFIG_HEADER + 1] = {
	[ETHTOOL_A_TSCONFIG_HEADER]		=
		NLA_POLICY_NESTED(ethnl_header_policy),
};

static int tsconfig_prepare_data(const struct ethnl_req_info *req_base,
				 struct ethnl_reply_data *reply_base,
				 const struct genl_info *info)
{
	struct tsconfig_reply_data *data = TSCONFIG_REPDATA(reply_base);
	struct hwtstamp_provider *hwtstamp = NULL;
	struct net_device *dev = reply_base->dev;
	struct kernel_hwtstamp_config cfg = {};
	int ret;

	if (!dev->netdev_ops->ndo_hwtstamp_get)
		return -EOPNOTSUPP;

	ret = ethnl_ops_begin(dev);
	if (ret < 0)
		return ret;

	ret = dev_get_hwtstamp_phylib(dev, &cfg);
	if (ret)
		goto out;

	data->hwtst_config.tx_type = BIT(cfg.tx_type);
	data->hwtst_config.rx_filter = BIT(cfg.rx_filter);
	data->hwtst_config.flags = BIT(cfg.flags);

	data->hwtst.index = -1;
	hwtstamp = rtnl_dereference(dev->hwtstamp);
	if (hwtstamp) {
		data->hwtst.index = ptp_clock_index(hwtstamp->ptp);
		data->hwtst.qualifier = hwtstamp->qualifier;
	}

out:
	ethnl_ops_complete(dev);
	return ret;
}

static int tsconfig_reply_size(const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	const struct tsconfig_reply_data *data = TSCONFIG_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	int len = 0;
	int ret;

	BUILD_BUG_ON(__HWTSTAMP_TX_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_FILTER_CNT > 32);

	if (data->hwtst_config.flags)
		/* _TSCONFIG_HWTSTAMP_FLAGS */
		len += nla_total_size(sizeof(u32));

	if (data->hwtst_config.tx_type) {
		ret = ethnl_bitset32_size(&data->hwtst_config.tx_type,
					  NULL, __HWTSTAMP_TX_CNT,
					  ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSCONFIG_TX_TYPES */
	}
	if (data->hwtst_config.rx_filter) {
		ret = ethnl_bitset32_size(&data->hwtst_config.rx_filter,
					  NULL, __HWTSTAMP_FILTER_CNT,
					  ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
		len += ret;	/* _TSCONFIG_RX_FILTERS */
	}

	if (data->hwtst.index >= 0)
		/* _TSCONFIG_HWTSTAMP_PROVIDER */
		len += nla_total_size(0) +
		       2 * nla_total_size(sizeof(u32));

	return len;
}

static int tsconfig_fill_reply(struct sk_buff *skb,
			       const struct ethnl_req_info *req_base,
			       const struct ethnl_reply_data *reply_base)
{
	const struct tsconfig_reply_data *data = TSCONFIG_REPDATA(reply_base);
	bool compact = req_base->flags & ETHTOOL_FLAG_COMPACT_BITSETS;
	int ret;

	if (data->hwtst_config.flags) {
		ret = nla_put_u32(skb, ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS,
				  data->hwtst_config.flags);
		if (ret < 0)
			return ret;
	}

	if (data->hwtst_config.tx_type) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSCONFIG_TX_TYPES,
					 &data->hwtst_config.tx_type, NULL,
					 __HWTSTAMP_TX_CNT,
					 ts_tx_type_names, compact);
		if (ret < 0)
			return ret;
	}

	if (data->hwtst_config.rx_filter) {
		ret = ethnl_put_bitset32(skb, ETHTOOL_A_TSCONFIG_RX_FILTERS,
					 &data->hwtst_config.rx_filter,
					 NULL, __HWTSTAMP_FILTER_CNT,
					 ts_rx_filter_names, compact);
		if (ret < 0)
			return ret;
	}

	if (data->hwtst.index >= 0) {
		struct nlattr *nest;

		nest = nla_nest_start(skb, ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER);
		if (!nest)
			return -EMSGSIZE;

		if (nla_put_u32(skb, ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX,
				data->hwtst.index) ||
		    nla_put_u32(skb,
				ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER,
				data->hwtst.qualifier)) {
			nla_nest_cancel(skb, nest);
			return -EMSGSIZE;
		}

		nla_nest_end(skb, nest);
	}
	return 0;
}

/* TSCONFIG_SET */
const struct nla_policy ethnl_tsconfig_set_policy[ETHTOOL_A_TSCONFIG_MAX + 1] = {
	[ETHTOOL_A_TSCONFIG_HEADER] = NLA_POLICY_NESTED(ethnl_header_policy),
	[ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER] = { .type = NLA_NESTED },
	[ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS] = { .type = NLA_U32 },
	[ETHTOOL_A_TSCONFIG_RX_FILTERS] = { .type = NLA_NESTED },
	[ETHTOOL_A_TSCONFIG_TX_TYPES] = { .type = NLA_NESTED },
};

static int tsconfig_send_reply(struct net_device *dev, struct genl_info *info)
{
	struct tsconfig_reply_data *reply_data;
	struct tsconfig_req_info *req_info;
	struct sk_buff *rskb;
	void *reply_payload;
	int reply_len = 0;
	int ret;

	req_info = kzalloc(sizeof(*req_info), GFP_KERNEL);
	if (!req_info)
		return -ENOMEM;
	reply_data = kmalloc(sizeof(*reply_data), GFP_KERNEL);
	if (!reply_data) {
		kfree(req_info);
		return -ENOMEM;
	}

	ASSERT_RTNL();
	reply_data->base.dev = dev;
	ret = tsconfig_prepare_data(&req_info->base, &reply_data->base, info);
	if (ret < 0)
		goto err_cleanup;

	ret = tsconfig_reply_size(&req_info->base, &reply_data->base);
	if (ret < 0)
		goto err_cleanup;

	reply_len = ret + ethnl_reply_header_size();
	rskb = ethnl_reply_init(reply_len, dev, ETHTOOL_MSG_TSCONFIG_SET_REPLY,
				ETHTOOL_A_TSCONFIG_HEADER, info, &reply_payload);
	if (!rskb)
		goto err_cleanup;

	ret = tsconfig_fill_reply(rskb, &req_info->base, &reply_data->base);
	if (ret < 0)
		goto err_cleanup;

	genlmsg_end(rskb, reply_payload);
	ret = genlmsg_reply(rskb, info);

err_cleanup:
	kfree(reply_data);
	kfree(req_info);
	return ret;
}

static int ethnl_set_tsconfig_validate(struct ethnl_req_info *req_base,
				       struct genl_info *info)
{
	const struct net_device_ops *ops = req_base->dev->netdev_ops;

	if (!ops->ndo_hwtstamp_set || !ops->ndo_hwtstamp_get)
		return -EOPNOTSUPP;

	return 1;
}

static int ethnl_set_tsconfig(struct ethnl_req_info *req_base,
			      struct genl_info *info)
{
	struct kernel_hwtstamp_config hwtst_config = {0}, _hwtst_config = {0};
	unsigned long mask = 0, req_rx_filter, req_tx_type;
	struct hwtstamp_provider *hwtstamp = NULL;
	struct net_device *dev = req_base->dev;
	struct nlattr **tb = info->attrs;
	bool mod = false;
	int ret;

	BUILD_BUG_ON(__HWTSTAMP_TX_CNT > 32);
	BUILD_BUG_ON(__HWTSTAMP_FILTER_CNT > 32);

	if (!netif_device_present(dev))
		return -ENODEV;

	if (tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER]) {
		struct hwtst_provider __hwtst = {.index = -1};
		struct hwtstamp_provider *__hwtstamp;

		__hwtstamp = rtnl_dereference(dev->hwtstamp);
		if (__hwtstamp) {
			__hwtst.index = ptp_clock_index(__hwtstamp->ptp);
			__hwtst.qualifier = __hwtstamp->qualifier;
		}

		ret = ts_parse_hwtst_provider(tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER],
					      &__hwtst, info->extack,
					      &mod);
		if (ret < 0)
			return ret;

		if (mod) {
			hwtstamp = kzalloc(sizeof(*hwtstamp), GFP_KERNEL);
			if (!hwtstamp)
				return -ENOMEM;

			hwtstamp->ptp = ptp_clock_get_by_index(&dev->dev,
							       __hwtst.index);
			if (!hwtstamp->ptp) {
				NL_SET_ERR_MSG_ATTR(info->extack,
						    tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER],
						    "no phc at such index");
				ret = -ENODEV;
				goto err_free_hwtstamp;
			}
			hwtstamp->qualifier = __hwtst.qualifier;
			hwtstamp->dev = &dev->dev;

			/* Does the hwtstamp supported in the netdev topology */
			if (!netdev_support_hwtstamp(dev, hwtstamp)) {
				NL_SET_ERR_MSG_ATTR(info->extack,
						    tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_PROVIDER],
						    "phc not in this net device topology");
				ret = -ENODEV;
				goto err_clock_put;
			}
		}
	}

	/* Get the hwtstamp config from netlink */
	if (tb[ETHTOOL_A_TSCONFIG_TX_TYPES]) {
		ret = ethnl_parse_bitset(&req_tx_type, &mask,
					 __HWTSTAMP_TX_CNT,
					 tb[ETHTOOL_A_TSCONFIG_TX_TYPES],
					 ts_tx_type_names, info->extack);
		if (ret < 0)
			goto err_clock_put;

		/* Select only one tx type at a time */
		if (ffs(req_tx_type) != fls(req_tx_type)) {
			ret = -EINVAL;
			goto err_clock_put;
		}

		hwtst_config.tx_type = ffs(req_tx_type) - 1;
	}
	if (tb[ETHTOOL_A_TSCONFIG_RX_FILTERS]) {
		ret = ethnl_parse_bitset(&req_rx_filter, &mask,
					 __HWTSTAMP_FILTER_CNT,
					 tb[ETHTOOL_A_TSCONFIG_RX_FILTERS],
					 ts_rx_filter_names, info->extack);
		if (ret < 0)
			goto err_clock_put;

		/* Select only one rx filter at a time */
		if (ffs(req_rx_filter) != fls(req_rx_filter)) {
			ret = -EINVAL;
			goto err_clock_put;
		}

		hwtst_config.rx_filter = ffs(req_rx_filter) - 1;
	}
	if (tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS]) {
		ret = nla_get_u32(tb[ETHTOOL_A_TSCONFIG_HWTSTAMP_FLAGS]);
		if (ret < 0)
			goto err_clock_put;
		hwtst_config.flags = ret;
	}

	ret = net_hwtstamp_validate(&hwtst_config);
	if (ret)
		goto err_clock_put;

	if (mod) {
		struct kernel_hwtstamp_config zero_config = {0};
		struct hwtstamp_provider *__hwtstamp;

		/* Disable current time stamping if we try to enable
		 * another one
		 */
		ret = dev_set_hwtstamp_phylib(dev, &zero_config, info->extack);
		if (ret < 0)
			goto err_clock_put;

		/* Change the selected hwtstamp source */
		__hwtstamp = rcu_replace_pointer_rtnl(dev->hwtstamp, hwtstamp);
		if (__hwtstamp)
			call_rcu(&__hwtstamp->rcu_head,
				 remove_hwtstamp_provider);
	} else {
		/* Get current hwtstamp config if we are not changing the
		 * hwtstamp source
		 */
		ret = dev_get_hwtstamp_phylib(dev, &_hwtst_config);
		if (ret < 0 && ret != -EOPNOTSUPP)
			goto err_clock_put;
	}

	if (memcmp(&hwtst_config, &_hwtst_config, sizeof(hwtst_config))) {
		ret = dev_set_hwtstamp_phylib(dev, &hwtst_config,
					      info->extack);
		if (ret < 0)
			return ret;

		ret = tsconfig_send_reply(dev, info);
		if (ret && ret != -EOPNOTSUPP) {
			NL_SET_ERR_MSG(info->extack,
				       "error while reading the new configuration set");
			return ret;
		}

		return 1;
	}

	if (mod)
		return 1;

	return 0;

err_clock_put:
	if (hwtstamp)
		ptp_clock_put(&dev->dev, hwtstamp->ptp);
err_free_hwtstamp:
	kfree(hwtstamp);

	return ret;
}

const struct ethnl_request_ops ethnl_tsconfig_request_ops = {
	.request_cmd		= ETHTOOL_MSG_TSCONFIG_GET,
	.reply_cmd		= ETHTOOL_MSG_TSCONFIG_GET_REPLY,
	.hdr_attr		= ETHTOOL_A_TSCONFIG_HEADER,
	.req_info_size		= sizeof(struct tsconfig_req_info),
	.reply_data_size	= sizeof(struct tsconfig_reply_data),

	.prepare_data		= tsconfig_prepare_data,
	.reply_size		= tsconfig_reply_size,
	.fill_reply		= tsconfig_fill_reply,

	.set_validate		= ethnl_set_tsconfig_validate,
	.set			= ethnl_set_tsconfig,
	.set_ntf_cmd		= ETHTOOL_MSG_TSCONFIG_NTF,
};
