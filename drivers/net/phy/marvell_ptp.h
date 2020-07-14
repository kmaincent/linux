/* SPDX-License-Identifier: GPL-2.0 */
#ifndef MARVELL_PTP_H
#define MARVELL_PTP_H

#if IS_ENABLED(CONFIG_MARVELL_PHY_PTP)
void marvell_ptp_check(struct phy_device *phydev);
int marvell_ptp_probe(struct phy_device *phydev);
void marvell_ptp_remove(struct phy_device *phydev);
#else
static inline int marvell_ptp_probe(struct phy_device *phydev)
{
	return 0;
}

static inline void marvell_ptp_remove(struct phy_device *phydev)
{
}
#endif

#endif
