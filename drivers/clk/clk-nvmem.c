// SPDX-License-Identifier: GPL-2.0-only
/*
 * Fixed rate clock that reads its frequency from NVMEM
 *
 * Copyright (C) 2023 Topic Embedded Products
 * Mike Looijmans <mike.looijmans@topic.nl>
 */

#include <linux/clk-provider.h>
#include <linux/module.h>
#include <linux/nvmem-consumer.h>
#include <linux/platform_device.h>
#include <linux/slab.h>

static int nvmemclk_retrieve(struct device *dev, const char *name, u32 *value)
{
	struct nvmem_cell *cell;
	const void *data;
	size_t len;
	int ret = 0;

	cell = of_nvmem_cell_get(dev->of_node, name);
	if (IS_ERR(cell))
		return PTR_ERR(cell);

	data = nvmem_cell_read(cell, &len);
	nvmem_cell_put(cell);

	if (IS_ERR(data))
		return PTR_ERR(data);

	/* Abort when all zeroes or all ones */
	if (!memchr_inv(data, 0, len) || !memchr_inv(data, 0xff, len)) {
		dev_warn(dev, "%s invalid, using default: %u\n", name, *value);
		goto exit_free_data;
	}

	switch (len) {
	case 1:
		*value = *(u8 *)data;
		break;
	case 2:
		*value = *(u16 *)data;
		break;
	case 4:
		*value = *(u32 *)data;
		break;
	case 8:
		*value = *(u64 *)data;
		break;
	default:
		ret = -EIO;
		break;
	}

exit_free_data:
	kfree(data);

	return ret;
}

static int nvmemclk_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	const char *clk_name = dev->of_node->name;
	struct clk_hw *hw;
	u32 rate;
	u32 accuracy = 0;
	int ret;

	of_property_read_u32(dev->of_node, "clock-frequency", &rate);
	ret = nvmemclk_retrieve(dev, "clock-frequency", &rate);
	if (ret < 0)
		return dev_err_probe(dev, ret,
				     "failed to access clock-frequency\n");

	/* clock-accuracy can be provided by either NVMEM or property */
	of_property_read_u32(dev->of_node, "clock-accuracy", &accuracy);
	ret = nvmemclk_retrieve(dev, "clock-accuracy", &accuracy);
	/* Only abort in case of deferral */
	if (ret == -EPROBE_DEFER)
		return ret;

	of_property_read_string(dev->of_node, "clock-output-names", &clk_name);

	hw = clk_hw_register_fixed_rate_with_accuracy(NULL, clk_name, NULL,
						      0, rate, accuracy);
	if (IS_ERR(hw))
		return dev_err_probe(dev, PTR_ERR(hw),
				     "Failed to register clock %s\n", clk_name);

	return devm_of_clk_add_hw_provider(dev, of_clk_hw_simple_get, hw);
}

static const struct of_device_id of_nvmemclk_ids[] = {
	{ .compatible = "fixed-clock-nvmem" },
	{ }
};
MODULE_DEVICE_TABLE(of, of_nvmemclk_ids);

static struct platform_driver nvmemclk_driver = {
	.driver = {
		.name = "fixed-clock-nvmem",
		.of_match_table = of_nvmemclk_ids,
	},
	.probe = nvmemclk_probe,
};

module_platform_driver(nvmemclk_driver);

MODULE_DESCRIPTION("NVMEM clock driver");
MODULE_AUTHOR("Mike Looijmans <mike.looijmans@topic.nl>");
MODULE_LICENSE("GPL");
