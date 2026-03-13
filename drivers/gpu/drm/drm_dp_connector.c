// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2026 Google
 * Author: Kory Maincent <kory.maincent@bootlin.com>
 */
#include <drm/drm_dp_connector.h>
#include <drm/drm_print.h>
#include <linux/list.h>

/**
 * drm_connector_dp_link_set_properties() - Set DisplayPort link configuration
 * @connector: DRM connector
 * @lanes: Number of lanes
 * @link_rate: Link rate in deca-kbps
 * @dsc_en: DSC enabled
 *
 * Returns: Zero on success, or an errno code otherwise.
 */
int
drm_connector_dp_set_link_properties(struct drm_connector *connector,
				     u32 lanes, u32 link_rate,
				     bool dsc_en)
{
	u32 lrate_bitmask = 0;
	int ret;

	if (!connector)
		return -ENODEV;

	if (lanes && !is_power_of_2(lanes & DRM_NLANES_MASK)) {
		drm_err(connector->dev, "Wrong lane number");
		return -EINVAL;
	}

	if (link_rate) {
		struct drm_property_enum *prop_enum;
		bool found = false;

		list_for_each_entry(prop_enum, &connector->dp.link_rate_property->enum_list, head) {
			u32 parsed_rate;

			/* Convert link_rate from deca-kbps to kbps */
			if (!kstrtou32(prop_enum->name, 10, &parsed_rate) &&
			    link_rate * 10 == parsed_rate) {
				lrate_bitmask = 1 << prop_enum->value;
				found = true;
				break;
			}
		}

		if (!found) {
			drm_err(connector->dev, "Wrong rate value");
			return -EINVAL;
		}
	}

	ret = drm_object_property_set_value(&connector->base,
					    connector->dp.nlanes_property,
					    lanes);
	if (ret)
		return ret;

	ret = drm_object_property_set_value(&connector->base,
					    connector->dp.link_rate_property,
					    lrate_bitmask);
	if (ret)
		return ret;

	if (connector->dp.dsc_en_property) {
		ret = drm_object_property_set_value(&connector->base,
						    connector->dp.dsc_en_property,
						    dsc_en);
		if (ret)
			return ret;
	}

	return ret;
}
EXPORT_SYMBOL(drm_connector_dp_set_link_properties);

/**
 * drm_connector_dp_link_reset_properties() - Reset DisplayPort link configuration
 * @connector: DRM connector
 */
void drm_connector_dp_reset_link_properties(struct drm_connector *connector)
{
	drm_connector_dp_set_link_properties(connector, 0, 0, 0);
}
EXPORT_SYMBOL(drm_connector_dp_reset_link_properties);

static int drm_connector_create_nlanes_prop(struct drm_connector *connector,
					    u8 sup_nlanes)
{
	static const struct drm_prop_enum_list props[] = {
		{__builtin_ffs(DRM_DP_1LANE) - 1, "1" },
		{__builtin_ffs(DRM_DP_2LANE) - 1, "2" },
		{__builtin_ffs(DRM_DP_4LANE) - 1, "4" },
	};
	struct drm_property *prop;

	if (drm_WARN_ON(connector->dev, sup_nlanes != (sup_nlanes & DRM_NLANES_MASK)))
		return -EINVAL;

	prop = drm_property_create_bitmask(connector->dev, DRM_MODE_PROP_IMMUTABLE,
					   "num_lanes", props, ARRAY_SIZE(props),
					   sup_nlanes);
	if (!prop)
		return -ENOMEM;

	drm_object_attach_property(&connector->base, prop, 0);

	connector->dp.nlanes_property = prop;

	return 0;
}

static int drm_connector_create_lrate_prop(struct drm_connector *connector,
					   u32 sup_nlrates,
					   const u32 *sup_lrates)
{
	struct drm_prop_enum_list *props;
	u32 supp_nlrates_bitmask = 0;
	struct drm_property *prop;
	int ret = 0;

	if (!sup_nlrates || !sup_lrates)
		return 0;

	props = kcalloc(sup_nlrates, sizeof(*props), GFP_KERNEL);
	if (!props)
		return -ENOMEM;

	for (int i = 0; i < sup_nlrates; i++) {
		props[i].type = i;
		/* Convert deca-kbps to kbps */
		props[i].name = kasprintf(GFP_KERNEL, "%d", sup_lrates[i] * 10);
		if (!props[i].name) {
			while (i--)
				kfree(props[i].name);
			kfree(props);
			return -ENOMEM;
		}
		supp_nlrates_bitmask |= 1 << i;
	}

	prop = drm_property_create_bitmask(connector->dev, DRM_MODE_PROP_IMMUTABLE,
					   "link_rate", props, sup_nlrates,
					   supp_nlrates_bitmask);
	if (!prop) {
		ret = -ENOMEM;
		goto out;
	}

	drm_object_attach_property(&connector->base, prop, 0);

	connector->dp.link_rate_property = prop;

out:
	for (int i = 0; i < sup_nlrates; i++)
		kfree(props[i].name);

	kfree(props);
	return ret;
}

static int drm_connector_create_dsc_prop(struct drm_connector *connector)
{
	struct drm_property *prop;

	prop = drm_property_create_bool(connector->dev, DRM_MODE_PROP_IMMUTABLE, "dsc_en");
	if (!prop)
		return -ENOMEM;

	drm_object_attach_property(&connector->base, prop, 0);

	connector->dp.dsc_en_property = prop;

	return 0;
}

static int
drm_connector_dp_create_props(struct drm_connector *connector,
			      const struct drm_connector_dp_link_caps *dp_link_caps)
{
	int ret;

	ret = drm_connector_create_nlanes_prop(connector, dp_link_caps->nlanes);
	if (ret)
		return ret;

	ret = drm_connector_create_lrate_prop(connector, dp_link_caps->nlink_rates,
					      dp_link_caps->link_rates);
	if (ret)
		return ret;

	if (dp_link_caps->dsc) {
		ret = drm_connector_create_dsc_prop(connector);
		if (ret)
			return ret;
	}

	return 0;
}

/**
 * drmm_connector_dp_init - Init a preallocated DisplayPort connector
 * @dev: DRM device
 * @connector: A pointer to the DisplayPort connector to init
 * @funcs: callbacks for this connector
 * @dp_link_caps: DisplayPort link training capabilities. The pointer
 *			is not kept by the DRM core
 * @connector_type: user visible type of the connector
 * @ddc: optional pointer to the associated ddc adapter
 *
 * Initialises a preallocated DisplayPort connector. Connectors can be
 * subclassed as part of driver connector objects.
 *
 * Cleanup is automatically handled with a call to
 * drm_connector_cleanup() in a DRM-managed action.
 *
 * The connector structure should be allocated with drmm_kzalloc().
 *
 * The @drm_connector_funcs.destroy hook must be NULL.
 *
 * Returns:
 * Zero on success, error code on failure.
 */
int drmm_connector_dp_init(struct drm_device *dev,
			   struct drm_connector *connector,
			   const struct drm_connector_funcs *funcs,
			   const struct drm_connector_dp_link_caps *dp_link_caps,
			   int connector_type,
			   struct i2c_adapter *ddc)
{
	int ret;

	if (!(connector_type == DRM_MODE_CONNECTOR_DisplayPort ||
	      connector_type == DRM_MODE_CONNECTOR_eDP))
		return -EINVAL;

	if (!dp_link_caps)
		return -EINVAL;

	ret = drmm_connector_init(dev, connector, funcs, connector_type, ddc);
	if (ret)
		return ret;

	return drm_connector_dp_create_props(connector, dp_link_caps);
}
EXPORT_SYMBOL(drmm_connector_dp_init);
