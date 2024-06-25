/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef _NET_ETHTOOL_TS_H
#define _NET_ETHTOOL_TS_H

#include "netlink.h"

struct hwtst_provider {
	int index;
	u32 qualifier;
};

static const struct nla_policy
ethnl_ts_hwtst_prov_policy[ETHTOOL_A_TS_HWTSTAMP_PROVIDER_MAX + 1] = {
	[ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX] =
		NLA_POLICY_MIN(NLA_S32, 0),
	[ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER] =
		NLA_POLICY_MAX(NLA_U32, HWTSTAMP_PROVIDER_QUALIFIER_CNT - 1)
};

static inline int ts_parse_hwtst_provider(const struct nlattr *nest,
					  struct hwtst_provider *hwtst,
					  struct netlink_ext_ack *extack,
					  bool *mod)
{
	struct nlattr *tb[ARRAY_SIZE(ethnl_ts_hwtst_prov_policy)];
	int ret;

	ret = nla_parse_nested(tb,
			       ARRAY_SIZE(ethnl_ts_hwtst_prov_policy) - 1,
			       nest,
			       ethnl_ts_hwtst_prov_policy, extack);
	if (ret < 0)
		return ret;

	if (NL_REQ_ATTR_CHECK(extack, nest, tb,
			      ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX) ||
	    NL_REQ_ATTR_CHECK(extack, nest, tb,
			      ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER))
		return -EINVAL;

	ethnl_update_u32(&hwtst->index,
			 tb[ETHTOOL_A_TS_HWTSTAMP_PROVIDER_INDEX],
			 mod);
	ethnl_update_u32(&hwtst->qualifier,
			 tb[ETHTOOL_A_TS_HWTSTAMP_PROVIDER_QUALIFIER],
			 mod);

	return 0;
}

#endif /* _NET_ETHTOOL_TS_H */
