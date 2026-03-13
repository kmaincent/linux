/* SPDX-License-Identifier: GPL-2.0-only */

#ifndef DRM_DP_CONNECTOR_H_
#define DRM_DP_CONNECTOR_H_

#include <drm/drm_connector.h>

int drmm_connector_dp_init(struct drm_device *dev,
			   struct drm_connector *connector,
			   const struct drm_connector_funcs *funcs,
			   const struct drm_connector_dp_link_caps *dp_link_caps,
			   int connector_type,
			   struct i2c_adapter *ddc);

int
drm_connector_dp_set_link_properties(struct drm_connector *connector,
                                     u32 lanes, u32 link_rate,
                                     bool dsc_en);

void drm_connector_dp_reset_link_properties(struct drm_connector *connector);

#endif // DRM_DP_CONNECTOR_H_
