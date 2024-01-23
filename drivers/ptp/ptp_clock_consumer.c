// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * PTP 1588 clock support
 *
 * Copyright (C) 2010 OMICRON electronics GmbH
 */
#include <linux/device.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/posix-clock.h>
#include <linux/pps_kernel.h>
#include <linux/slab.h>
#include <linux/syscalls.h>
#include <linux/uaccess.h>
#include <linux/debugfs.h>
#include <linux/xarray.h>
#include <uapi/linux/sched/types.h>

#include "ptp_private.h"

DEFINE_XARRAY_ALLOC(ptp_clocks_map);
EXPORT_SYMBOL(ptp_clocks_map);

bool ptp_clock_from_phylib(struct ptp_clock *ptp)
{
	return ptp->phc_source == HWTSTAMP_SOURCE_PHYLIB;
}

bool ptp_clock_from_netdev(struct ptp_clock *ptp)
{
	return ptp->phc_source == HWTSTAMP_SOURCE_NETDEV;
}

struct net_device *ptp_clock_netdev(struct ptp_clock *ptp)
{
	if (ptp->phc_source != HWTSTAMP_SOURCE_NETDEV)
		return NULL;

	return ptp->netdev;
}

struct phy_device *ptp_clock_phydev(struct ptp_clock *ptp)
{
	if (ptp->phc_source != HWTSTAMP_SOURCE_PHYLIB)
		return NULL;

	return ptp->phydev;
}
EXPORT_SYMBOL(ptp_clock_phydev);

int ptp_clock_get(struct device *dev, struct ptp_clock *ptp)
{
	struct device_link *link;

	if (!ptp)
		return 0;

	if (!try_module_get(ptp->info->owner))
		return -EPROBE_DEFER;

	get_device(&ptp->dev);

	link = device_link_add(dev, &ptp->dev, DL_FLAG_STATELESS);
	if (!link)
		dev_warn(dev, "failed to create device link to %s\n",
			 dev_name(&ptp->dev));

	return 0;
}

struct ptp_clock *ptp_clock_get_by_index(struct device *dev, int index)
{
	struct ptp_clock *ptp;
	int ret;

	if (index < 0)
		return NULL;

	ptp = xa_load(&ptp_clocks_map, (unsigned long)index);
	if (IS_ERR_OR_NULL(ptp))
		return ptp;

	ret = ptp_clock_get(dev, ptp);
	if (ret)
		return ERR_PTR(ret);

	return ptp;
}

void ptp_clock_put(struct device *dev, struct ptp_clock *ptp)
{
	if (!ptp)
		return;

	device_link_remove(dev, &ptp->dev);
	put_device(&ptp->dev);
	module_put(ptp->info->owner);
}

void remove_hwtstamp_provider(struct rcu_head *rcu_head)
{
	struct hwtstamp_provider *hwtstamp;

	hwtstamp = container_of(rcu_head, struct hwtstamp_provider, rcu_head);
	ptp_clock_put(hwtstamp->dev, hwtstamp->ptp);
	kfree(hwtstamp);
}
EXPORT_SYMBOL(remove_hwtstamp_provider);
