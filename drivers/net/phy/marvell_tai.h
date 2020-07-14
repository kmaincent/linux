/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MARVELL_TAI_H
#define MARVELL_TAI_H

#include <linux/list.h>
#include <linux/mutex.h>
#include <linux/ptp_clock_kernel.h>
#include <linux/timecounter.h>

struct phy_device;

struct marvell_tai {
	struct list_head tai_node;
	struct phy_device *phydev;

	struct ptp_clock_info caps;
	struct ptp_clock *ptp_clock;

	u32 cc_mult_num;
	u32 cc_mult_den;
	u32 cc_mult;

	struct mutex mutex;
	struct timecounter timecounter;
	struct cyclecounter cyclecounter;
	long half_overflow_period;

	/* Used while reading the TAI */
	struct ptp_system_timestamp *sts;
};

u64 marvell_tai_cyc2time(struct marvell_tai *tai, u32 cyc);
int marvell_tai_get(struct marvell_tai **taip, struct phy_device *phydev);
void marvell_tai_put(struct marvell_tai *tai);

#endif
