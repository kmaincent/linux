// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for the TI TPS23881 PoE PSE Controller driver (I2C bus)
 *
 * Copyright (c) 2023 Bootlin, Kory Maincent <kory.maincent@bootlin.com>
 */

#include <linux/bitfield.h>
#include <linux/delay.h>
#include <linux/firmware.h>
#include <linux/gpio/consumer.h>
#include <linux/i2c.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pse-pd/pse.h>

#define TPS23881_MAX_CHANS 8

#define TPS23881_REG_IT		0x0
#define TPS23881_REG_IT_MASK	0x1
#define TPS23881_REG_IT_IFAULT	BIT(5)
#define TPS23881_REG_IT_SUPF	BIT(7)
#define TPS23881_REG_FAULT	0x7
#define TPS23881_REG_SUPF_EVENT	0xb
#define TPS23881_REG_TSD	BIT(7)
#define TPS23881_REG_PW_STATUS	0x10
#define TPS23881_REG_OP_MODE	0x12
#define TPS23881_OP_MODE_SEMIAUTO	0xaaaa
#define TPS23881_REG_DIS_EN	0x13
#define TPS23881_REG_DET_CLA_EN	0x14
#define TPS23881_REG_PW_PRIO	0x15
#define TPS23881_REG_GEN_MASK	0x17
#define TPS23881_REG_NBITACC	BIT(5)
#define TPS23881_REG_INTEN	BIT(7)
#define TPS23881_REG_PW_EN	0x19
#define TPS23881_REG_2PAIR_POL1	0x1e
#define TPS23881_REG_PORT_MAP	0x26
#define TPS23881_REG_PORT_POWER	0x29
#define TPS23881_REG_4PAIR_POL1	0x2a
#define TPS23881_REG_INPUT_V	0x2e
#define TPS23881_REG_CHAN1_A	0x30
#define TPS23881_REG_CHAN1_V	0x32
#define TPS23881_REG_POEPLUS	0x40
#define TPS23881_REG_TPON	BIT(0)
#define TPS23881_REG_FWREV	0x41
#define TPS23881_REG_DEVID	0x43
#define TPS23881_REG_DEVID_MASK	0xF0
#define TPS23881_DEVICE_ID	0x02
#define TPS23881_REG_CHAN1_CLASS	0x4c
#define TPS23881_REG_SRAM_CTRL	0x60
#define TPS23881_REG_SRAM_DATA	0x61

#define TPS23881_UV_STEP	3662
#define TPS23881_MAX_UV		60000000
#define TPS23881_NA_STEP	70190
#define TPS23881_MAX_UA		1150000
#define TPS23881_MW_STEP	500

struct tps23881_port_desc {
	u8 chan[2];
	bool is_4p;
};

struct tps23881_priv {
	struct i2c_client *client;
	struct pse_controller_dev pcdev;
	struct device_node *np;
	struct tps23881_port_desc port[TPS23881_MAX_CHANS];
	struct gpio_desc *oss;
};

static struct tps23881_priv *to_tps23881_priv(struct pse_controller_dev *pcdev)
{
	return container_of(pcdev, struct tps23881_priv, pcdev);
}

static int tps23881_pi_enable(struct pse_controller_dev *pcdev, int id)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	u8 chan;
	u16 val;
	int ret;

	if (id >= TPS23881_MAX_CHANS)
		return -ERANGE;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_STATUS);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4)
		val = (u16)(ret | BIT(chan));
	else
		val = (u16)(ret | BIT(chan + 4));

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4)
			val |= BIT(chan);
		else
			val |= BIT(chan + 4);
	}

	ret = i2c_smbus_write_word_data(client, TPS23881_REG_PW_EN, val);
	if (ret)
		return ret;

	return 0;
}

static int tps23881_pi_disable(struct pse_controller_dev *pcdev, int id)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	u8 chan;
	u16 val;
	int ret;

	if (id >= TPS23881_MAX_CHANS)
		return -ERANGE;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_STATUS);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4)
		val = (u16)(ret | BIT(chan + 4));
	else
		val = (u16)(ret | BIT(chan + 8));

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4)
			val |= BIT(chan + 4);
		else
			val |= BIT(chan + 8);
	}

	return i2c_smbus_write_word_data(client, TPS23881_REG_PW_EN, val);
}

static int tps23881_pi_is_enabled(struct pse_controller_dev *pcdev, int id)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	bool enabled;
	u8 chan;
	int ret;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_STATUS);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4)
		enabled = !!(ret & BIT(chan));
	else
		enabled = !!(ret & BIT(chan + 4));

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4)
			enabled &= !!(ret & BIT(chan));
		else
			enabled &= !!(ret & BIT(chan + 4));
	}

	/* Return enabled status only if both channel are on this state */
	return enabled;
}

static int tps23881_pi_get_voltage(struct pse_controller_dev *pcdev, int id)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	int ret, reg;
	u8 chan;
	u64 uV;

	/* Read Voltage only at one of the 2-pair ports */
	chan = priv->port[id].chan[0];
	if (chan < 4)
		/* Registers 0x32 0x36 0x3a 0x3e */
		reg = TPS23881_REG_CHAN1_V + chan * 4;
	else
		/* Registers 0x33 0x37 0x3b 0x3f */
		reg = TPS23881_REG_CHAN1_V + 1 + (chan % 4) * 4;

	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	uV = ret;
	uV *= TPS23881_UV_STEP;
	if (uV > TPS23881_MAX_UV) {
		dev_err(&client->dev, "voltage read out of range\n");
		return -ERANGE;
	}

	return (int)uV;
}

static int
tps23881_pi_get_chan_current(struct tps23881_priv *priv, u8 chan)
{
	struct i2c_client *client = priv->client;
	int reg, ret;
	u64 tmp_64;

	if (chan < 4)
		/* Registers 0x30 0x34 0x38 0x3c */
		reg = TPS23881_REG_CHAN1_A + chan * 4;
	else
		/* Registers 0x31 0x35 0x39 0x3d */
		reg = TPS23881_REG_CHAN1_A + 1 + (chan % 4) * 4;

	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	tmp_64 = ret;
	tmp_64 *= TPS23881_NA_STEP;
	/* uA = nA / 1000 */
	tmp_64 = DIV_ROUND_CLOSEST_ULL(tmp_64, 1000);
	if (tmp_64 > TPS23881_MAX_UA) {
		dev_err(&client->dev, "current read out of range\n");
		return -ERANGE;
	}
	return (int)tmp_64;
}

static int
tps23881_pi_get_power(struct tps23881_priv *priv, unsigned long id)
{
	int ret, uV, uA;
	u64 tmp_64;
	u8 chan;

	ret = tps23881_pi_get_voltage(&priv->pcdev, id);
	if (ret < 0)
		return ret;
	uV = ret;

	chan = priv->port[id].chan[0];
	ret = tps23881_pi_get_chan_current(priv, chan);
	if (ret < 0)
		return ret;
	uA = ret;

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		ret = tps23881_pi_get_chan_current(priv, chan);
		if (ret < 0)
			return ret;
		uA += ret;
	}

	tmp_64 = uV;
	tmp_64 *= uA;
	/* mW = uV * uA / 1000000000 */
	return DIV_ROUND_CLOSEST_ULL(tmp_64, 1000000000);
}

static int
tps23881_pi_get_pw_limit_chan(struct tps23881_priv *priv, u8 chan)
{
	struct i2c_client *client = priv->client;
	int ret, reg, mW;

	reg = TPS23881_REG_2PAIR_POL1 + (chan % 4);
	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	if (chan < 4)
		mW = (ret & 0xff) * TPS23881_MW_STEP;
	else
		mW = (ret >> 8) * TPS23881_MW_STEP;

	return mW;
}

static int tps23881_pi_get_pw_limit(struct tps23881_priv *priv, int id)
{
	int ret, mW;
	u8 chan;

	chan = priv->port[id].chan[0];
	ret = tps23881_pi_get_pw_limit_chan(priv, chan);
	if (ret < 0)
		return ret;

	mW = ret;
	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		ret = tps23881_pi_get_pw_limit_chan(priv, chan);
		if (ret < 0)
			return ret;
		mW += ret;
	}

	return mW;
}

static int tps23881_pi_get_max_pw_limit(struct tps23881_priv *priv, int id)
{
	int ret, uV;
	u64 tmp_64;

	ret = tps23881_pi_get_voltage(&priv->pcdev, id);
	if (ret < 0)
		return ret;
	uV = ret;

	tmp_64 = uV;
	tmp_64 *= MAX_PI_CURRENT;
	/* mW = uV * uA / 1000000000 */
	return DIV_ROUND_CLOSEST_ULL(tmp_64, 1000000000);
}

static int tps23881_pi_get_class(struct tps23881_priv *priv, int id)
{
	struct i2c_client *client = priv->client;
	int ret, reg, class;
	u8 chan;

	chan = priv->port[id].chan[0];
	reg = TPS23881_REG_CHAN1_CLASS + (chan % 4);
	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	if (chan < 4)
		class = ret >> 4;
	else
		class = ret >> 12;

	return class;
}

static int tps23881_ethtool_get_status(struct pse_controller_dev *pcdev,
				       unsigned long id,
				       struct netlink_ext_ack *extack,
				       struct pse_control_status *status)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	bool enabled, delivering;
	u8 chan;
	int ret;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_STATUS);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4) {
		enabled = !!(ret & BIT(chan));
		delivering = !!(ret & BIT(chan + 4));
	} else {
		enabled = !!(ret & BIT(chan + 4));
		delivering = !!(ret & BIT(chan + 8));
	}

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4) {
			enabled &= !!(ret & BIT(chan));
			delivering &= !!(ret & BIT(chan + 4));
		} else {
			enabled &= !!(ret & BIT(chan + 4));
			delivering &= !!(ret & BIT(chan + 8));
		}
	}

	/* Return delivering status only if both channel are on this state */
	if (delivering)
		status->c33_pw_status = ETHTOOL_C33_PSE_PW_D_STATUS_DELIVERING;
	else
		status->c33_pw_status = ETHTOOL_C33_PSE_PW_D_STATUS_DISABLED;

	/* Return enabled status only if both channel are on this state */
	if (enabled)
		status->c33_admin_state = ETHTOOL_C33_PSE_ADMIN_STATE_ENABLED;
	else
		status->c33_admin_state = ETHTOOL_C33_PSE_ADMIN_STATE_DISABLED;

	ret = tps23881_pi_get_power(priv, id);
	if (ret < 0)
		return ret;
	status->c33_actual_pw = ret;

	status->c33_pw_limit_ranges = kzalloc(sizeof(*status->c33_pw_limit_ranges),
					      GFP_KERNEL);
	if (!status->c33_pw_limit_ranges)
		return -ENOMEM;

	status->c33_actual_pw = ret;

	ret = tps23881_pi_get_max_pw_limit(priv, id);
	if (ret < 0)
		return ret;
	status->c33_pw_limit_nb_ranges = 1;
	status->c33_pw_limit_ranges->min = 2000;
	status->c33_pw_limit_ranges->max = ret;

	ret = tps23881_pi_get_pw_limit(priv, id);
	if (ret < 0)
		return ret;
	status->c33_avail_pw_limit = ret;

	ret = tps23881_pi_get_class(priv, id);
	if (ret < 0)
		return ret;
	status->c33_pw_class = ret;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_PRIO);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4)
		status->c33_prio = !!(ret & BIT(chan + 4));
	else
		status->c33_prio = !!(ret & BIT(chan + 8));

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4)
			status->c33_prio &= !!(ret & BIT(chan + 4));
		else
			status->c33_prio &= !!(ret & BIT(chan + 8));
	}

	return 0;
}

/* Parse managers subnode into a array of device node */
static int
tps23881_get_of_channels(struct tps23881_priv *priv,
			 struct device_node *chan_node[TPS23881_MAX_CHANS])
{
	struct device_node *channels_node, *node;
	int i, ret;

	if (!priv->np)
		return -EINVAL;

	channels_node = of_find_node_by_name(priv->np, "channels");
	if (!channels_node)
		return -EINVAL;

	for_each_child_of_node(channels_node, node) {
		u32 chan_id;

		if (!of_node_name_eq(node, "channel"))
			continue;

		ret = of_property_read_u32(node, "reg", &chan_id);
		if (ret) {
			ret = -EINVAL;
			goto out;
		}

		if (chan_id >= TPS23881_MAX_CHANS || chan_node[chan_id]) {
			dev_err(&priv->client->dev,
				"wrong number of port (%d)\n", chan_id);
			ret = -EINVAL;
			goto out;
		}

		of_node_get(node);
		chan_node[chan_id] = node;
	}

	of_node_put(channels_node);
	return 0;

out:
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		of_node_put(chan_node[i]);
		chan_node[i] = NULL;
	}

	of_node_put(node);
	of_node_put(channels_node);
	return ret;
}

struct tps23881_port_matrix {
	u8 pi_id;
	u8 lgcl_chan[2];
	u8 hw_chan[2];
	bool is_4p;
	bool exist;
};

static int
tps23881_match_channel(const struct pse_pi_pairset *pairset,
		       struct device_node *chan_node[TPS23881_MAX_CHANS])
{
	int i;

	/* Look on every channels */
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		if (pairset->np == chan_node[i])
			return i;
	}

	return -ENODEV;
}

static bool
tps23881_is_chan_free(struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS],
		      int chan)
{
	int i;

	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		if (port_matrix[i].exist &&
		    (port_matrix[i].hw_chan[0] == chan ||
		    port_matrix[i].hw_chan[1] == chan))
			return false;
	}

	return true;
}

/* Fill port matrix with the matching channels */
static int
tps23881_match_port_matrix(struct pse_pi *pi, int pi_id,
			   struct device_node *chan_node[TPS23881_MAX_CHANS],
			   struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS])
{
	int ret;

	if (!pi->pairset[0].np)
		return 0;

	ret = tps23881_match_channel(&pi->pairset[0], chan_node);
	if (ret < 0)
		return ret;

	if (!tps23881_is_chan_free(port_matrix, ret)) {
		pr_err("tps23881: channel %d already used\n", ret);
		return -ENODEV;
	}

	port_matrix[pi_id].hw_chan[0] = ret;
	port_matrix[pi_id].exist = true;

	if (!pi->pairset[1].np)
		return 0;

	ret = tps23881_match_channel(&pi->pairset[1], chan_node);
	if (ret < 0)
		return ret;

	if (!tps23881_is_chan_free(port_matrix, ret)) {
		pr_err("tps23881: channel %d already used\n", ret);
		return -ENODEV;
	}

	if (port_matrix[pi_id].hw_chan[0] / 4 != ret / 4) {
		pr_err("tps23881: 4-pair PSE can only be set within the same 4 ports group");
		return -ENODEV;
	}

	port_matrix[pi_id].hw_chan[1] = ret;
	port_matrix[pi_id].is_4p = true;

	return 0;
}

static int
tps23881_get_unused_chan(struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS],
			 int port_cnt)
{
	bool used;
	int i, j;

	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		used = false;

		for (j = 0; j < port_cnt; j++) {
			if (port_matrix[j].hw_chan[0] == i) {
				used = true;
				break;
			}

			if (port_matrix[j].is_4p &&
			    port_matrix[j].hw_chan[1] == i) {
				used = true;
				break;
			}
		}

		if (!used)
			return i;
	}

	return -ENODEV;
}

/* Sort the port matrix to following particular hardware ports matrix
 * specification of the tps23881. The device has two 4-ports groups and
 * each 4-pair powered device has to be configured to use two consecutive
 * logical channel in each 4 ports group (1 and 2 or 3 and 4). Also the
 * hardware matrix has to be fully configured even with unused chan to be
 * valid.
 */
static int
tps23881_sort_port_matrix(struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS])
{
	struct tps23881_port_matrix tmp_port_matrix[TPS23881_MAX_CHANS] = {0};
	int i, ret, port_cnt = 0, cnt_4ch_grp1 = 0, cnt_4ch_grp2 = 4;

	/* Configure 4p port matrix */
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		int *cnt;

		if (!port_matrix[i].exist || !port_matrix[i].is_4p)
			continue;

		if (port_matrix[i].hw_chan[0] < 4)
			cnt = &cnt_4ch_grp1;
		else
			cnt = &cnt_4ch_grp2;

		tmp_port_matrix[port_cnt].exist = true;
		tmp_port_matrix[port_cnt].is_4p = true;
		tmp_port_matrix[port_cnt].pi_id = i;
		tmp_port_matrix[port_cnt].hw_chan[0] = port_matrix[i].hw_chan[0];
		tmp_port_matrix[port_cnt].hw_chan[1] = port_matrix[i].hw_chan[1];

		/* 4-pair ports have to be configured with consecutive
		 * logical channels 0 and 1, 2 and 3.
		 */
		tmp_port_matrix[port_cnt].lgcl_chan[0] = (*cnt)++;
		tmp_port_matrix[port_cnt].lgcl_chan[1] = (*cnt)++;

		port_cnt++;
	}

	/* Configure 2p port matrix */
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		int *cnt;

		if (!port_matrix[i].exist || port_matrix[i].is_4p)
			continue;

		if (port_matrix[i].hw_chan[0] < 4)
			cnt = &cnt_4ch_grp1;
		else
			cnt = &cnt_4ch_grp2;

		tmp_port_matrix[port_cnt].exist = true;
		tmp_port_matrix[port_cnt].pi_id = i;
		tmp_port_matrix[port_cnt].lgcl_chan[0] = (*cnt)++;
		tmp_port_matrix[port_cnt].hw_chan[0] = port_matrix[i].hw_chan[0];

		port_cnt++;
	}

	/* Complete the rest of the first 4 port group matrix even if
	 * channels are unused
	 */
	while (cnt_4ch_grp1 < 4) {
		ret = tps23881_get_unused_chan(tmp_port_matrix, port_cnt);
		if (ret < 0) {
			pr_err("tps23881: port matrix issue, no chan available\n");
			return ret;
		}

		if (port_cnt >= TPS23881_MAX_CHANS) {
			pr_err("tps23881: wrong number of channels\n");
			return -ENODEV;
		}
		tmp_port_matrix[port_cnt].lgcl_chan[0] = cnt_4ch_grp1;
		tmp_port_matrix[port_cnt].hw_chan[0] = ret;
		cnt_4ch_grp1++;
		port_cnt++;
	}

	/* Complete the rest of the second 4 port group matrix even if
	 * channels are unused
	 */
	while (cnt_4ch_grp2 < 8) {
		ret = tps23881_get_unused_chan(tmp_port_matrix, port_cnt);
		if (ret < 0) {
			pr_err("tps23881: port matrix issue, no chan available\n");
			return -ENODEV;
		}

		if (port_cnt >= TPS23881_MAX_CHANS) {
			pr_err("tps23881: wrong number of channels\n");
			return -ENODEV;
		}
		tmp_port_matrix[port_cnt].lgcl_chan[0] = cnt_4ch_grp2;
		tmp_port_matrix[port_cnt].hw_chan[0] = ret;
		cnt_4ch_grp2++;
		port_cnt++;
	}

	memcpy(port_matrix, tmp_port_matrix, sizeof(tmp_port_matrix));

	return port_cnt;
}

/* Write port matrix to the hardware port matrix and the software port
 * matrix.
 */
static int
tps23881_write_port_matrix(struct tps23881_priv *priv,
			   struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS],
			   int port_cnt)
{
	struct i2c_client *client = priv->client;
	u8 pi_id, lgcl_chan, hw_chan;
	u16 val = 0;
	int i;

	for (i = 0; i < port_cnt; i++) {
		pi_id = port_matrix[i].pi_id;
		lgcl_chan = port_matrix[i].lgcl_chan[0];
		hw_chan = port_matrix[i].hw_chan[0] % 4;

		/* Set software port matrix for existing ports */
		if (port_matrix[i].exist)
			priv->port[pi_id].chan[0] = lgcl_chan;

		/* Set hardware port matrix for all ports */
		val |= hw_chan << (lgcl_chan * 2);

		if (!port_matrix[i].is_4p)
			continue;

		lgcl_chan = port_matrix[i].lgcl_chan[1];
		hw_chan = port_matrix[i].hw_chan[1] % 4;

		/* Set software port matrix for existing ports */
		if (port_matrix[i].exist) {
			priv->port[pi_id].is_4p = true;
			priv->port[pi_id].chan[1] = lgcl_chan;
		}

		/* Set hardware port matrix for all ports */
		val |= hw_chan << (lgcl_chan * 2);
	}

	/* Write hardware ports matrix */
	return i2c_smbus_write_word_data(client, TPS23881_REG_PORT_MAP, val);
}

static int
tps23881_set_ports_conf(struct tps23881_priv *priv,
			struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS])
{
	struct i2c_client *client = priv->client;
	int i, ret;
	u16 val;

	/* Set operating mode */
	ret = i2c_smbus_write_word_data(client, TPS23881_REG_OP_MODE,
					TPS23881_OP_MODE_SEMIAUTO);
	if (ret)
		return ret;

	/* Disable DC disconnect */
	ret = i2c_smbus_write_word_data(client, TPS23881_REG_DIS_EN, 0x0);
	if (ret)
		return ret;

	/* Set port power allocation */
	val = 0;
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		if (!port_matrix[i].exist)
			continue;

		if (port_matrix[i].is_4p)
			val |= 0xf << ((port_matrix[i].lgcl_chan[0] / 2) * 4);
		else
			val |= 0x3 << ((port_matrix[i].lgcl_chan[0] / 2) * 4);
	}
	ret = i2c_smbus_write_word_data(client, TPS23881_REG_PORT_POWER, val);
	if (ret)
		return ret;

	/* Enable detection and classification */
	val = 0;
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		if (!port_matrix[i].exist)
			continue;

		val |= BIT(port_matrix[i].lgcl_chan[0]) |
		       BIT(port_matrix[i].lgcl_chan[0] + 4);
		if (port_matrix[i].is_4p)
			val |= BIT(port_matrix[i].lgcl_chan[1]) |
			       BIT(port_matrix[i].lgcl_chan[1] + 4);
	}
	return i2c_smbus_write_word_data(client, TPS23881_REG_DET_CLA_EN, val);
}

static int
tps23881_set_ports_matrix(struct tps23881_priv *priv,
			  struct device_node *chan_node[TPS23881_MAX_CHANS])
{
	struct tps23881_port_matrix port_matrix[TPS23881_MAX_CHANS] = {0};
	int i, ret;

	/* Update with values for every PSE PIs */
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		ret = tps23881_match_port_matrix(&priv->pcdev.pi[i], i,
						 chan_node, port_matrix);
		if (ret)
			return ret;
	}

	ret = tps23881_sort_port_matrix(port_matrix);
	if (ret < 0)
		return ret;

	ret = tps23881_write_port_matrix(priv, port_matrix, ret);
	if (ret)
		return ret;

	return tps23881_set_ports_conf(priv, port_matrix);
}

static int tps23881_setup_pi_matrix(struct pse_controller_dev *pcdev)
{
	struct device_node *chan_node[TPS23881_MAX_CHANS] = {NULL};
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	int ret, i;

	ret = tps23881_get_of_channels(priv, chan_node);
	if (ret < 0) {
		dev_warn(&priv->client->dev,
			 "Unable to parse port-matrix, default matrix will be used\n");
		return 0;
	}

	ret = tps23881_set_ports_matrix(priv, chan_node);

	for (i = 0; i < TPS23881_MAX_CHANS; i++)
		of_node_put(chan_node[i]);

	return ret;
}

static int tps23881_pi_get_current_limit(struct pse_controller_dev *pcdev,
					 int id)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	int ret, mW, uV;
	u64 tmp_64;

	ret = tps23881_pi_get_pw_limit(priv, id);
	if (ret < 0)
		return ret;
	mW = ret;

	ret = tps23881_pi_get_voltage(pcdev, id);
	if (ret < 0)
		return ret;
	uV = ret;

	tmp_64 = mW;
	tmp_64 *= 1000000000ull;
	/* uA = mW * 1000000000 / uV */
	return DIV_ROUND_CLOSEST_ULL(tmp_64, uV);
}

static int
tps23881_pi_set_2p_pw_limit(struct tps23881_priv *priv, u8 chan, u8 pol)
{
	struct i2c_client *client = priv->client;
	int ret, reg;
	u16 val;

	reg = TPS23881_REG_2PAIR_POL1 + (chan % 4);
	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	if (chan < 4)
		val = (ret & 0xff00) | pol;
	else
		val = (ret & 0xff) | (pol << 8);

	return i2c_smbus_write_word_data(client, reg, val);
}

static int
tps23881_pi_set_4p_pw_limit(struct tps23881_priv *priv, u8 chan, u8 pol)
{
	struct i2c_client *client = priv->client;
	int ret, reg;
	u16 val;

	if ((chan % 4) < 2)
		reg = TPS23881_REG_4PAIR_POL1;
	else
		reg = TPS23881_REG_4PAIR_POL1 + 1;

	ret = i2c_smbus_read_word_data(client, reg);
	if (ret < 0)
		return ret;

	if (chan < 4)
		val = (ret & 0xff00) | pol;
	else
		val = (ret & 0xff) | (pol << 8);

	return i2c_smbus_write_word_data(client, reg, val);
}

static int tps23881_pi_set_current_limit(struct pse_controller_dev *pcdev,
					 int id, int max_uA)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	u8 chan, pw_pol;
	int ret, mW;
	u64 tmp_64;

	ret = tps23881_pi_get_voltage(pcdev, id);
	if (ret < 0)
		return ret;

	tmp_64 = ret;
	tmp_64 *= max_uA;
	/* mW = uV * uA / 1000000000 */
	mW = DIV_ROUND_CLOSEST_ULL(tmp_64, 1000000000);
	pw_pol = DIV_ROUND_CLOSEST_ULL(mW, TPS23881_MW_STEP);

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[0];
		/* One chan is enough to configure the PI power limit */
		ret = tps23881_pi_set_4p_pw_limit(priv, chan, pw_pol);
		if (ret < 0)
			return ret;
	} else {
		chan = priv->port[id].chan[0];
		ret = tps23881_pi_set_2p_pw_limit(priv, chan, pw_pol);
		if (ret < 0)
			return ret;
	}

	return 0;
}

static int tps23881_pi_set_prio(struct pse_controller_dev *pcdev, int id,
				unsigned int prio)
{
	struct tps23881_priv *priv = to_tps23881_priv(pcdev);
	struct i2c_client *client = priv->client;
	u8 chan, bit;
	u16 val;
	int ret;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_PW_PRIO);
	if (ret < 0)
		return ret;

	chan = priv->port[id].chan[0];
	if (chan < 4)
		bit = chan + 4;
	else
		bit = chan + 8;

	val = (u16)(ret & ~BIT(bit));
	val |= prio << (bit);

	if (priv->port[id].is_4p) {
		chan = priv->port[id].chan[1];
		if (chan < 4)
			bit = chan + 4;
		else
			bit = chan + 8;

		val &= ~BIT(bit);
		val |= prio << (bit);
	}

	return i2c_smbus_write_word_data(client, TPS23881_REG_PW_PRIO, val);
}

static const struct pse_controller_ops tps23881_ops = {
	.setup_pi_matrix = tps23881_setup_pi_matrix,
	.pi_enable = tps23881_pi_enable,
	.pi_disable = tps23881_pi_disable,
	.pi_is_enabled = tps23881_pi_is_enabled,
	.ethtool_get_status = tps23881_ethtool_get_status,
	.pi_get_voltage = tps23881_pi_get_voltage,
	.pi_get_current_limit = tps23881_pi_get_current_limit,
	.pi_set_current_limit = tps23881_pi_set_current_limit,
	.pi_set_prio = tps23881_pi_set_prio,
};

static const char fw_parity_name[] = "ti/tps23881/tps23881-parity-14.bin";
static const char fw_sram_name[] = "ti/tps23881/tps23881-sram-14.bin";

struct tps23881_fw_conf {
	u8 reg;
	u8 val;
};

static const struct tps23881_fw_conf tps23881_fw_parity_conf[] = {
	{.reg = 0x60, .val = 0x01},
	{.reg = 0x62, .val = 0x00},
	{.reg = 0x63, .val = 0x80},
	{.reg = 0x60, .val = 0xC4},
	{.reg = 0x1D, .val = 0xBC},
	{.reg = 0xD7, .val = 0x02},
	{.reg = 0x91, .val = 0x00},
	{.reg = 0x90, .val = 0x00},
	{.reg = 0xD7, .val = 0x00},
	{.reg = 0x1D, .val = 0x00},
	{ /* sentinel */ }
};

static const struct tps23881_fw_conf tps23881_fw_sram_conf[] = {
	{.reg = 0x60, .val = 0xC5},
	{.reg = 0x62, .val = 0x00},
	{.reg = 0x63, .val = 0x80},
	{.reg = 0x60, .val = 0xC0},
	{.reg = 0x1D, .val = 0xBC},
	{.reg = 0xD7, .val = 0x02},
	{.reg = 0x91, .val = 0x00},
	{.reg = 0x90, .val = 0x00},
	{.reg = 0xD7, .val = 0x00},
	{.reg = 0x1D, .val = 0x00},
	{ /* sentinel */ }
};

static int tps23881_flash_sram_fw_part(struct i2c_client *client,
				       const char *fw_name,
				       const struct tps23881_fw_conf *fw_conf)
{
	const struct firmware *fw = NULL;
	int i, ret;

	ret = request_firmware(&fw, fw_name, &client->dev);
	if (ret)
		return ret;

	dev_dbg(&client->dev, "Flashing %s\n", fw_name);

	/* Prepare device for RAM download */
	while (fw_conf->reg) {
		ret = i2c_smbus_write_byte_data(client, fw_conf->reg,
						fw_conf->val);
		if (ret)
			goto out;

		fw_conf++;
	}

	/* Flash the firmware file */
	for (i = 0; i < fw->size; i++) {
		ret = i2c_smbus_write_byte_data(client,
						TPS23881_REG_SRAM_DATA,
						fw->data[i]);
		if (ret)
			goto out;
	}

out:
	release_firmware(fw);
	return ret;
}

static int tps23881_flash_sram_fw(struct i2c_client *client)
{
	int ret;

	ret = tps23881_flash_sram_fw_part(client, fw_parity_name,
					  tps23881_fw_parity_conf);
	if (ret)
		return ret;

	ret = tps23881_flash_sram_fw_part(client, fw_sram_name,
					  tps23881_fw_sram_conf);
	if (ret)
		return ret;

	ret = i2c_smbus_write_byte_data(client, TPS23881_REG_SRAM_CTRL, 0x18);
	if (ret)
		return ret;

	mdelay(12);

	return 0;
}

static void tps23881_turn_off_low_prio(struct tps23881_priv *priv)
{
	dev_info(&priv->client->dev,
		 "turn off low priority ports due to over current event.\n");
	gpiod_set_value_cansleep(priv->oss, 1);

	/* TPS23880 datasheet (Rev G) indicates minimum OSS pulse is 5us */
	usleep_range(5, 10);
	gpiod_set_value_cansleep(priv->oss, 0);
}

static int tps23881_irq_handler(int irq, struct pse_irq_data *pid,
				unsigned long *dev_mask)
{
	struct tps23881_priv *priv = (struct tps23881_priv *)pid->data;
	struct i2c_client *client = priv->client;
	struct pse_err_state *stat;
	int ret, i;
	u16 val;

	*dev_mask = 0;
	for (i = 0; i < TPS23881_MAX_CHANS; i++) {
		stat = &pid->states[i];
		stat->notifs = 0;
		stat->errors = 0;
	}

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_IT);
	if (ret < 0)
		return PSE_FAILED_RETRY;

	val = (u16)ret;
	if (val & TPS23881_REG_IT_SUPF) {
		ret = i2c_smbus_read_word_data(client, TPS23881_REG_SUPF_EVENT);
		if (ret < 0)
			return PSE_FAILED_RETRY;

		if (ret & TPS23881_REG_TSD) {
			for (i = 0; i < TPS23881_MAX_CHANS; i++) {
				stat = &pid->states[i];
				*dev_mask |= 1 << i;
				stat->notifs = PSE_EVENT_OVER_TEMP;
				stat->errors = PSE_ERROR_OVER_TEMP;
			}
		}
	}

	if (val & (TPS23881_REG_IT_IFAULT | TPS23881_REG_IT_IFAULT << 8)) {
		ret = i2c_smbus_read_word_data(client, TPS23881_REG_FAULT);
		if (ret < 0)
			return PSE_FAILED_RETRY;

		val = (u16)(ret & 0xf0f);

		/* Power cut detected, shutdown low priority port */
		if (val && priv->oss)
			tps23881_turn_off_low_prio(priv);

		*dev_mask |= val;
		for (i = 0; i < TPS23881_MAX_CHANS; i++) {
			if (val & BIT(i)) {
				stat = &pid->states[i];
				stat->notifs = PSE_EVENT_OVER_CURRENT;
				stat->errors = PSE_ERROR_OVER_CURRENT;
			}
		}
	}

	return PSE_ERROR_CLEARED;
}

static int tps23881_setup_irq(struct tps23881_priv *priv, int irq)
{
	int errs = PSE_ERROR_OVER_CURRENT | PSE_ERROR_OVER_TEMP;
	struct i2c_client *client = priv->client;
	struct pse_irq_desc irq_desc = {
		.name = "tps23881-irq",
		.map_event = tps23881_irq_handler,
		.data = priv,
	};
	int ret;
	u16 val;

	val = TPS23881_REG_IT_IFAULT | TPS23881_REG_IT_SUPF |
	      TPS23881_REG_IT_IFAULT << 8 | TPS23881_REG_IT_SUPF << 8;
	ret = i2c_smbus_write_word_data(client, TPS23881_REG_IT_MASK, val);
	if (ret)
		return ret;

	ret = i2c_smbus_read_word_data(client, TPS23881_REG_GEN_MASK);
	if (ret < 0)
		return ret;

	val = (u16)(ret | TPS23881_REG_INTEN | TPS23881_REG_INTEN << 8);
	ret = i2c_smbus_write_word_data(client, TPS23881_REG_GEN_MASK, val);
	if (ret < 0)
		return ret;

	return devm_pse_irq_helper(&priv->pcdev, irq, 0, errs, &irq_desc);
}

static int tps23881_i2c_probe(struct i2c_client *client)
{
	struct device *dev = &client->dev;
	struct tps23881_priv *priv;
	struct gpio_desc *reset, *oss;
	int ret;
	u8 val;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(dev, "i2c check functionality failed\n");
		return -ENXIO;
	}

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	reset = devm_gpiod_get_optional(dev, "reset", GPIOD_OUT_HIGH);
	if (IS_ERR(reset))
		return dev_err_probe(&client->dev, PTR_ERR(reset), "Failed to get reset GPIO\n");

	if (reset) {
		/* TPS23880 datasheet (Rev G) indicates minimum reset pulse is 5us */
		usleep_range(5, 10);
		gpiod_set_value_cansleep(reset, 0); /* De-assert reset */

		/* TPS23880 datasheet indicates the minimum time after power on reset
		 * should be 20ms, but the document describing how to load SRAM ("How
		 * to Load TPS2388x SRAM and Parity Code over I2C" (Rev E))
		 * indicates we should delay that programming by at least 50ms. So
		 * we'll wait the entire 50ms here to ensure we're safe to go to the
		 * SRAM loading proceedure.
		 */
		msleep(50);
	}

	ret = i2c_smbus_read_byte_data(client, TPS23881_REG_DEVID);
	if (ret < 0)
		return ret;

	if (FIELD_GET(TPS23881_REG_DEVID_MASK, ret) != TPS23881_DEVICE_ID) {
		dev_err(dev, "Wrong device ID\n");
		return -ENXIO;
	}

	ret = tps23881_flash_sram_fw(client);
	if (ret < 0)
		return ret;

	ret = i2c_smbus_read_byte_data(client, TPS23881_REG_FWREV);
	if (ret < 0)
		return ret;

	dev_info(&client->dev, "Firmware revision 0x%x\n", ret);

	/* Set configuration B, 16 bit access on a single device address */
	ret = i2c_smbus_read_byte_data(client, TPS23881_REG_GEN_MASK);
	if (ret < 0)
		return ret;

	val = ret | TPS23881_REG_NBITACC;
	ret = i2c_smbus_write_byte_data(client, TPS23881_REG_GEN_MASK, val);
	if (ret)
		return ret;

	priv->client = client;
	i2c_set_clientdata(client, priv);
	priv->np = dev->of_node;

	priv->pcdev.owner = THIS_MODULE;
	priv->pcdev.ops = &tps23881_ops;
	priv->pcdev.dev = dev;
	priv->pcdev.types = ETHTOOL_PSE_C33;
	priv->pcdev.nr_lines = TPS23881_MAX_CHANS;
	priv->pcdev.pis_prio_max = 1;
	ret = devm_pse_controller_register(dev, &priv->pcdev);
	if (ret) {
		return dev_err_probe(dev, ret,
				     "failed to register PSE controller\n");
	}

	oss = devm_gpiod_get_optional(dev, "oss", GPIOD_OUT_LOW);
	if (IS_ERR(oss))
		return dev_err_probe(&client->dev, PTR_ERR(oss), "Failed to get OSS GPIO\n");
	priv->oss = oss;

	if (client->irq) {
		ret = tps23881_setup_irq(priv, client->irq);
		if (ret)
			return ret;
	}

	return ret;
}

static const struct i2c_device_id tps23881_id[] = {
	{ "tps23881" },
	{ }
};
MODULE_DEVICE_TABLE(i2c, tps23881_id);

static const struct of_device_id tps23881_of_match[] = {
	{ .compatible = "ti,tps23881", },
	{ },
};
MODULE_DEVICE_TABLE(of, tps23881_of_match);

static struct i2c_driver tps23881_driver = {
	.probe		= tps23881_i2c_probe,
	.id_table	= tps23881_id,
	.driver		= {
		.name		= "tps23881",
		.of_match_table = tps23881_of_match,
	},
};
module_i2c_driver(tps23881_driver);

MODULE_AUTHOR("Kory Maincent <kory.maincent@bootlin.com>");
MODULE_DESCRIPTION("TI TPS23881 PoE PSE Controller driver");
MODULE_LICENSE("GPL");
