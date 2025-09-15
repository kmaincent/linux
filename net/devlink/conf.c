// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (c) 2025 Bootlin, Kory Maincent <kory.maincent@bootlin.com>
 */

#include "devl_internal.h"

int devlink_nl_conf_set_doit(struct sk_buff *skb, struct genl_info *info)
{
	struct devlink *devlink = info->user_ptr[0];
	struct nlattr **tb = info->attrs;
	const struct devlink_ops *ops;

	ops = devlink->ops;
	if (!ops->conf_save || !ops->conf_reset)
		return -EOPNOTSUPP;

	if (tb[DEVLINK_ATTR_CONF_SAVE] && tb[DEVLINK_ATTR_CONF_RESET]) {
		NL_SET_ERR_MSG_MOD(info->extack,
				   "Can't save and reset the configuration simultaneously");
		return -EINVAL;
	}

	if (tb[DEVLINK_ATTR_CONF_SAVE])
		return ops->conf_save(devlink, info->extack);

	if (tb[DEVLINK_ATTR_CONF_RESET])
		return ops->conf_reset(devlink, info->extack);

	return 0;
}
