// SPDX-License-Identifier: GPL-2.0-only
/*
 * Driver for the Microchip PD692X0 PoE PSE Controller driver (I2C bus)
 *
 * Copyright (c) 2023 Bootlin, Kory Maincent <kory.maincent@bootlin.com>
 */

#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pse-pd/pse.h>
#include <linux/i2c.h>
#include <linux/delay.h>
#include <linux/firmware.h>

#define PD692X0_PSE_NAME "pd692x0_pse"

#define PD692X0_MAX_PORTS	48
#define PD692X0_MAX_HW_PORTS	96
#define PD692X0_MSG_LEN		15
#define PD692X0_MSG_CHKSUM_LEN	2

#define PD69200_BT_PROD_VER	24
#define PD69210_BT_PROD_VER	26
#define PD69220_BT_PROD_VER	29

#define PD692X0_FW_MAJ_VER	3
#define PD692X0_FW_MIN_VER	5
#define PD692X0_FW_PATCH_VER	5

enum pd692x0_fw_state {
	PD692X0_FW_UNKNOWN,
	PD692X0_FW_OK,
	PD692X0_FW_BROKEN,
	PD692X0_FW_NEED_UPDATE,
	PD692X0_FW_PREPARE,
	PD692X0_FW_WRITE,
	PD692X0_FW_COMPLETE,
};

struct pd692x0_msg_content {
	u8 key;
	u8 echo;
	u8 sub[3];
	u8 data[8];
	u16 chksum;
} __packed;

struct pd692x0_msg_ver {
	u8 prod;
	u8 maj_sw_ver;
	u8 min_sw_ver;
	u8 pa_sw_ver;
	u8 param;
	u8 build;
};

enum {
	PD692X0_KEY_CMD,
	PD692X0_KEY_PRG,
	PD692X0_KEY_REQ,
	PD692X0_KEY_TLM,
	PD692X0_KEY_TEST,
	PD692X0_KEY_REPORT = 0x52
};

enum {
	PD692X0_MSG_RESET,
	PD692X0_MSG_GET_SYS_STAT,
	PD692X0_MSG_GET_SW_VER,
	PD692X0_MSG_SET_MASK,
	PD692X0_MSG_GET_ACTIVE_PORT_MATRIX,
	PD692X0_MSG_GET_TMP_PORT_MATRIX,
	PD692X0_MSG_SET_TMP_PORT_MATRIX,
	PD692X0_MSG_PRG_PORT_MATRIX,
	PD692X0_MSG_FUNC_4P,
	PD692X0_MSG_SET_PORT_PARAM,
	PD692X0_MSG_GET_PORT_STATUS,
	PD692X0_MSG_DOWNLOAD_CMD,

        /* add new message above here */
        PD692X0_MSG_CNT
};

struct pd692x0_msg {
	struct pd692x0_msg_content content;
	u16 delay_recv;
};

struct pd692x0_priv {
	struct i2c_client *client;
	struct pse_controller_dev pcdev;

	enum pd692x0_fw_state fw_state;
	struct fw_upload *fwl;
	bool cancel_request:1;
	unsigned pse_prod_num;

	u8 msg_id;
	bool last_cmd_key:1;
	unsigned long last_cmd_key_time;

	u16 port_matrix[PD692X0_MAX_PORTS];

	enum ethtool_pse_admin_state admin_state[PD692X0_MAX_PORTS];
};

// DEBUG
static void pd692x0_dump_msg(struct pd692x0_msg_content *msg)
{
	int i;
	u8 *data = (u8 *)msg;
	for (i = 0; i < PD692X0_MSG_LEN; i++)
		printk(KERN_CONT "%02i ", i);
	printk(KERN_CONT "\n");
	for (i = 0; i < PD692X0_MSG_LEN; i++)
		printk(KERN_CONT "%02x ", *(data + i));
	printk(KERN_CONT "\n");
}

struct pd692x0_msg pd692x0_msg_list[PD692X0_MSG_CNT] = {
	[PD692X0_MSG_RESET] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.echo = 0xff,
			.sub = {0x07, 0x55, 0x00},
			.data = {0x55, 0x00, 0x55, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
		.delay_recv = 300,
	},
	[PD692X0_MSG_GET_SYS_STAT] = {
		.content = {
			.key = PD692X0_KEY_REQ,
			.sub = {0x07, 0xd0, 0x4e},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_GET_SW_VER] = {
		.content = {
			.key = PD692X0_KEY_REQ,
			.sub = {0x07, 0x1e, 0x21},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_SET_MASK] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.sub = {0x07, 0x56},
			.data = {   0, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_GET_ACTIVE_PORT_MATRIX] = {
		.content = {
			.key = PD692X0_KEY_REQ,
			.sub = {0x05, 0x44},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_GET_TMP_PORT_MATRIX] = {
		.content = {
			.key = PD692X0_KEY_REQ,
			.sub = {0x05, 0x43},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_SET_TMP_PORT_MATRIX] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.sub	 = {0x05, 0x43},
			.data = {   0, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_PRG_PORT_MATRIX] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.sub = {0x07, 0x43, 0x4e},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_FUNC_4P] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.sub = {0x05, 0x02},
			.data = {   0, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_SET_PORT_PARAM] = {
		.content = {
			.key = PD692X0_KEY_CMD,
			.sub = {0x05, 0xc0},
			.data = {   0, 0xff, 0xff, 0xff,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_GET_PORT_STATUS] = {
		.content = {
			.key = PD692X0_KEY_REQ,
			.sub = {0x05, 0xc1},
			.data = {0x4e, 0x4e, 0x4e, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
	[PD692X0_MSG_DOWNLOAD_CMD] = {
		.content = {
			.key = PD692X0_KEY_PRG,
			.sub = {0xff, 0x99, 0x15},
			.data = {0x16, 0x16, 0x99, 0x4e,
				 0x4e, 0x4e, 0x4e, 0x4e},
		},
	},
};

static int pd692x0_reset(struct pd692x0_priv *priv);

u8 pd692x0_build_msg(struct pd692x0_msg_content *msg, u8 echo)
{
	u16 chksum = 0;
	int i;

	u8 *data = (u8 *)msg;
	if (!msg->echo) {
		msg->echo = echo++;
		if (echo == 0xff)
			echo = 0;
	}

	for (i = 0; i < (PD692X0_MSG_LEN - PD692X0_MSG_CHKSUM_LEN); i++)
		chksum += *(data + i);

	msg->chksum = cpu_to_be16(chksum);

	return echo;
}

static int pd692x0_send_msg(struct pd692x0_priv *priv,
		         struct pd692x0_msg *msg)
{
	struct i2c_client *client = priv->client;
	int ret;

	if (msg->content.key == PD692X0_KEY_CMD && priv->last_cmd_key) {
		while(time_is_after_jiffies(msecs_to_jiffies(30) + priv->last_cmd_key_time))
			msleep(1);
	}

	priv->msg_id = pd692x0_build_msg(&msg->content, priv->msg_id);

	ret = i2c_master_send(client, (u8 *)&msg->content, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return -EIO;;

	return 0;
}

static int pd692x0_recv_msg(struct pd692x0_priv *priv,
		            struct pd692x0_msg *msg,
		            struct pd692x0_msg_content *buf)
{
	struct i2c_client *client = priv->client;
	int ret;

	if (msg->delay_recv)
		msleep(msg->delay_recv);
	else
		msleep(30);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	msleep(100);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	ret = pd692x0_send_msg(priv, msg);
	if (ret)
		return ret;

	if (msg->delay_recv)
		msleep(msg->delay_recv);
	else
		msleep(30);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	msleep(100);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	msleep(10000);

	ret = pd692x0_send_msg(priv, msg);
	if (ret)
		return ret;

	if (msg->delay_recv)
		msleep(msg->delay_recv);
	else
		msleep(30);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	msleep(100);

	ret = i2c_master_recv(client, (u8 *)buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf->key)
		goto out;

	return pd692x0_reset(priv);

out:
	if (msg->content.key == PD692X0_KEY_CMD) {
		priv->last_cmd_key = true;
		priv->last_cmd_key_time = jiffies;
	} else
		priv->last_cmd_key = false;

	return 0;
}

static int pd692x0_sendrecv_msg(struct pd692x0_priv *priv,
		         struct pd692x0_msg msg,
			 struct pd692x0_msg_content *buf)
{
	struct device *dev = &priv->client->dev;
	int ret;

	pr_err("SEND \n");
	pd692x0_dump_msg(&msg.content);

	ret = pd692x0_send_msg(priv, &msg);
	if (ret)
		return ret;

	ret = pd692x0_recv_msg(priv, &msg, buf);
	if (ret)
		return ret;

	pr_err("RCV \n");
	pd692x0_dump_msg(buf);

	if (msg.content.echo != buf->echo) {
		dev_err(dev, "Wrong match in message ID(%d != %d)\n", msg.content.echo, buf->echo);
		return -EIO;
	}

	if (buf->key == PD692X0_KEY_REPORT &&
	    (buf->sub[0] || buf->sub[1])) {
		dev_err(dev, "Communication error\n");
		return -EIO;
	}

	return 0;
}


static struct pd692x0_priv *to_pd692x0_priv(struct pse_controller_dev *pcdev)
{
	return container_of(pcdev, struct pd692x0_priv, pcdev);
}

static int pd692x0_fw_unavailable(struct pd692x0_priv *priv)
{
	switch (priv->fw_state) {
	case PD692X0_FW_OK:
		return 0;
		break;
	case PD692X0_FW_PREPARE:
	case PD692X0_FW_WRITE:
	case PD692X0_FW_COMPLETE:
		dev_err(&priv->client->dev, "Firmware update in progress!\n");
		return -EBUSY;
	case PD692X0_FW_BROKEN:
	case PD692X0_FW_NEED_UPDATE:
	default:
		dev_err(&priv->client->dev, "Firmware issue. Please update it!\n");
		return -EOPNOTSUPP;
	}
}

static int pd692x0_ethtool_set_config(struct pse_controller_dev *pcdev,
				      unsigned long id,
				      struct netlink_ext_ack *extack,
				      const struct pse_control_config *config)
{
	struct pd692x0_msg msg = pd692x0_msg_list[PD692X0_MSG_SET_PORT_PARAM];
	struct pd692x0_priv *priv = to_pd692x0_priv(pcdev);
	struct pd692x0_msg_content buf = {0};
	int ret;

	ret = pd692x0_fw_unavailable(priv);
	if (ret)
		return ret;

	pr_err("%s admin_ctrl %d\n", __func__, config->admin_control);
	if (priv->admin_state[id] == config->admin_control)
		return 0;

	switch (config->admin_control) {
	case ETHTOOL_PSE_ADMIN_STATE_ENABLED:
		msg.content.data[0] = 0x1;
		break;
	case ETHTOOL_PSE_ADMIN_STATE_DISABLED:
		msg.content.data[0] = 0x0;
		break;
	default:
		dev_err(pcdev->dev, "Unknown admin state %i\n",
			config->admin_control);
		return -EOPNOTSUPP;
	}

	msg.content.sub[2] = id;

	ret = pd692x0_sendrecv_msg(priv, msg, &buf);
	if (ret < 0)
		return ret;

	priv->admin_state[id] = config->admin_control;

	return 0;
}

static int pd692x0_ethtool_get_status(struct pse_controller_dev *pcdev,
				      unsigned long id,
				      struct netlink_ext_ack *extack,
				      struct pse_control_status *status)
{
	struct pd692x0_msg msg = pd692x0_msg_list[PD692X0_MSG_GET_PORT_STATUS];
	struct pd692x0_priv *priv = to_pd692x0_priv(pcdev);
	struct pd692x0_msg_content buf = {0};
	int ret;

	ret = pd692x0_fw_unavailable(priv);
	if (ret)
		return ret;

	msg.content.sub[2] = id;
	ret = pd692x0_sendrecv_msg(priv, msg, &buf);
	if (ret < 0)
		return ret;

	if ((buf.sub[0] & 0xf0) == 0x80 || (buf.sub[0] & 0xf0) == 0x90)
		status->pw_status = ETHTOOL_PSE_PW_D_STATUS_DELIVERING;
	else if (buf.sub[0] == 0x1b || buf.sub[0] == 0x22)
		status->pw_status = ETHTOOL_PSE_PW_D_STATUS_SEARCHING;
	else if (buf.sub[0] == 0x12)
		status->pw_status = ETHTOOL_PSE_PW_D_STATUS_FAULT;
	else
		status->pw_status = ETHTOOL_PSE_PW_D_STATUS_DISABLED;

	if (buf.sub[1])
		status->admin_state = ETHTOOL_PSE_ADMIN_STATE_ENABLED;
	else
		status->admin_state = ETHTOOL_PSE_ADMIN_STATE_DISABLED;

	priv->admin_state[id] = status->admin_state;

	return 0;
}

static struct pd692x0_msg_ver pd692x0_get_sw_version(struct pd692x0_priv *priv)
{
	struct device *dev = &priv->client->dev;
	struct pd692x0_msg_content buf = {0};
	struct pd692x0_msg_ver ver = {0};
	int ret;

	ret = pd692x0_sendrecv_msg(priv, pd692x0_msg_list[PD692X0_MSG_GET_SW_VER], &buf);
	if (ret < 0) {
		dev_err(dev, "failed to get PSE version (%pe)\n", ERR_PTR(ret));
	}

	ver.prod = buf.sub[2];
	ver.maj_sw_ver = (buf.data[0] << 8 | buf.data[1]) / 100;
	ver.min_sw_ver = ((buf.data[0] << 8 | buf.data[1]) / 10) % 10;
	ver.pa_sw_ver = (buf.data[0] << 8 | buf.data[1]) % 10;
	ver.param = buf.data[2];
	ver.build = buf.data[3];

	return ver;
}

static int pd692x0_reset(struct pd692x0_priv *priv)
{
	struct pd692x0_msg msg = pd692x0_msg_list[PD692X0_MSG_RESET];
	struct i2c_client *client = priv->client;
	struct pd692x0_msg_content buf = {0};
	int ret;

	ret = pd692x0_send_msg(priv, &msg);
	if (ret)
		return ret;

	msleep(30);

	ret = i2c_master_recv(client, (u8 *)&buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf.key == PD692X0_KEY_REPORT &&
	    (buf.sub[0] || buf.sub[1])) {
		dev_err(&client->dev, "Communication error\n");
		return -EIO;
	}

	msleep(300);

	ret = i2c_master_recv(client, (u8 *)&buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content))
		return ret < 0 ? ret : -EIO;

	if (buf.key != 0x03 || buf.echo != 0xff || buf.sub[0] & 0x1) {
		dev_err(&client->dev, "PSE controller error\n");
		return -EIO;
	}

	return 0;
}

static const struct pse_controller_ops pd692x0_ops = {
	.ethtool_get_status = pd692x0_ethtool_get_status,
	.ethtool_set_config = pd692x0_ethtool_set_config,
};

static void pd692x0_dump_ports_matrix(struct pd692x0_priv *priv)
{
	struct i2c_client *client = priv->client;
	struct pd692x0_msg msg;
	struct pd692x0_msg_content buf = {0};
	int ret = 0, i;

	dev_err(&client->dev, "get temp matrix port (%pe)\n", ERR_PTR(ret));
	msg = pd692x0_msg_list[PD692X0_MSG_GET_TMP_PORT_MATRIX];
	for (i = 0; i < PD692X0_MAX_PORTS; i++)
	{
		msg.content.sub[2] = i;
		ret = pd692x0_sendrecv_msg(priv, msg, &buf);
		if (ret < 0) {
			dev_err(&client->dev, "failed to get matrix port (%pe)\n", ERR_PTR(ret));
			return;
		}
	}

	dev_err(&client->dev, "get active matrix port (%pe)\n", ERR_PTR(ret));
	msg = pd692x0_msg_list[PD692X0_MSG_GET_ACTIVE_PORT_MATRIX];
	for (i = 0; i < PD692X0_MAX_PORTS; i++)
	{
		msg.content.sub[2] = i;
		ret = pd692x0_sendrecv_msg(priv, msg, &buf);
		if (ret < 0) {
			dev_err(&client->dev, "failed to get matrix port (%pe)\n", ERR_PTR(ret));
			return;
		}
	}

}

static int pd692x0_set_ports_matrix(struct pd692x0_priv *priv, u8 port_matrix[PD692X0_MAX_PORTS][3], int num_ports)
{
	struct i2c_client *client = priv->client;
	struct pd692x0_msg msg = {0};
	struct pd692x0_msg_content buf = {0};
	int ret, i;

//	for (i = 0; i < num_ports; i++) {
//		if (port_matrix[i][2] != 0xff) {
//			is_4p = true;
//			break;
//		}
//	}
//
//	if (is_4p) {
//		msg = pd692x0_msg_list[PD692X0_MSG_SET_MASK];
//		msg.content.sub[2] = 0x34;
//		msg.content.data[0] = 0x1;
//		ret = pd692x0_sendrecv_msg(priv, msg, &buf);
//		if (ret < 0) {
//			dev_err(&client->dev, "failed to set mask 0x34 (%pe)\n", ERR_PTR(ret));
//			return ret;
//		}
//	}

	msg = pd692x0_msg_list[PD692X0_MSG_SET_TMP_PORT_MATRIX];
	for (i = 0; i < PD692X0_MAX_PORTS; i++) {
		bool found = false;
		int j;

		for (j = 0; j < num_ports; j++) {
			if (i == port_matrix[j][0]) {
				found = true;
				break;
			}
		}

		msg.content.sub[2] = i;
		if (found) {
			msg.content.data[0] = port_matrix[j][1];
			msg.content.data[1] = port_matrix[j][2];
		} else {
			msg.content.data[0] = 0xff;
			msg.content.data[1] = 0xff;
		}

		ret = pd692x0_sendrecv_msg(priv, msg, &buf);
		if (ret < 0) {
			dev_err(&client->dev, "failed to set matrix port (%pe)\n", ERR_PTR(ret));
			return ret;
		}
	}

	msg = pd692x0_msg_list[PD692X0_MSG_PRG_PORT_MATRIX];
	ret = pd692x0_sendrecv_msg(priv, msg, &buf);
	if (ret < 0) {
		dev_err(&client->dev, "failed to program new port matrix (%pe)\n", ERR_PTR(ret));
		return ret;
	}

//	for (i = 0; i < num_ports; i++) {
//		if (port_matrix[i][2] != 0xff) {
//			msg = pd692x0_msg_list[PD692X0_MSG_FUNC_4P];
//			msg.content.sub[2] = i;
//			msg.content.data[0] = 0x1;
//			ret = pd692x0_sendrecv_msg(priv, msg, &buf);
//			if (ret < 0) {
//				dev_err(&client->dev, "failed to enable 4 pair function (%pe)\n", ERR_PTR(ret));
//				return ret;
//			}
//		}
//	}

	return 0;
}

static int pd692x0_get_of_matrix(struct device *dev,
				 u8 matrix[PD692X0_MAX_PORTS][3])
{
	int ret, i, port_num, ports_matrix_size;
	u32 val[PD692X0_MAX_PORTS * 3];

	ports_matrix_size = device_property_count_u32(dev, "ports-matrix");
	if (ports_matrix_size <= 0)
		return -EINVAL;
	if (ports_matrix_size % 3 ||
	    ports_matrix_size > PD692X0_MAX_PORTS * 3) {
		dev_err(dev, "no valid ports-matrix property size: %d\n",
			ports_matrix_size);
		return -EINVAL;
	}

	ret = device_property_read_u32_array(dev, "ports-matrix", val,
					     ports_matrix_size);
	if (ret < 0)
		return ret;

	for (i = 0, port_num = 0; i < ports_matrix_size; i += 3, port_num++) {
		if (val[i] >= PD692X0_MAX_PORTS ||
		    val[i + 1] >= PD692X0_MAX_HW_PORTS ||
		    val[i + 2] >= PD692X0_MAX_HW_PORTS) {
			pr_err("%d %d %d\n", val[i], val[i + 1], val[i + 2]);
			dev_err(dev, "No valid ports-matrix property\n");
			return -ERANGE;
		}

		matrix[port_num][0] = (u8)val[i];
		matrix[port_num][1] = (u8)val[i + 1];
		if (!val[i + 2])
			matrix[port_num][2] = 0xff;
		else
			matrix[port_num][2] = (u8)val[i + 2];
		pr_err("%s, ch %d hw_A %d hw_B %d\n", __func__, matrix[port_num][0], matrix[port_num][1], matrix[port_num][2]);
	}
	return port_num;
}

static int pd692x0_update_matrix(struct pd692x0_priv *priv)
{
	u8 port_matrix[PD692X0_MAX_PORTS][3] = {0};
	struct device *dev = &priv->client->dev;
	int ret, num_ports;

	num_ports = pd692x0_get_of_matrix(dev, port_matrix);
	if (num_ports <= 0) {
		dev_warn(dev, "Unable to parse port-matrix, saved matrix will be used\n");
		return 0;
	}

	ret = pd692x0_set_ports_matrix(priv, port_matrix, num_ports);
	if (ret < 0) {
		return ret;
	}

	return 0;
}

#define PD692X0_FW_LINE_MAX_SZ 128
static int pd692x0_fw_get_next_line(const u8 *data,
				    char line[PD692X0_FW_LINE_MAX_SZ])
{
	int i;

	memset(line, 0, PD692X0_FW_LINE_MAX_SZ);
	for (i = 0; i < PD692X0_FW_LINE_MAX_SZ; i++)
	{
		if (data[0] == '\r' && data[1] == '\n') {
			line[0] = '\r';
			line[1] = '\n';
			return i + 2;
		}
		line[0] = data[0];
		line++;
		data++;
	}
	return 0;
}

static enum fw_upload_err
pd692x0_fw_recv_resp(struct i2c_client *client, const unsigned long ms_timeout,
		     const char *msg_ok, const unsigned msg_size)
{
	char *fw_msg_buf = NULL;
	unsigned long timeout;
	int ret;

	fw_msg_buf = kzalloc(msg_size, GFP_KERNEL);
	if (!fw_msg_buf) {
		dev_err(&client->dev, "Failed to allocate memory\n");
		return FW_UPLOAD_ERR_MEM_ERROR;
	}

	timeout = msecs_to_jiffies(ms_timeout) + jiffies;
	while(true) {
		if (time_is_before_jiffies(timeout)) {
			ret = FW_UPLOAD_ERR_TIMEOUT;
			break;
		}

		ret = i2c_master_recv(client, fw_msg_buf, msg_size - sizeof(char));
		if (ret < 0 || fw_msg_buf[0] == 0) {
			msleep(1);
			continue;
		}

		if (!strcmp(fw_msg_buf, msg_ok)) {
//			dev_err(&client->dev, "well received %*pE\n", msg_size, msg_ok);
			ret = FW_UPLOAD_ERR_NONE;
			break;
		} else {
			dev_err(&client->dev,
			"Wrong download process answer(%*pE)\n", msg_size, fw_msg_buf);
			ret = FW_UPLOAD_ERR_HW_ERROR;
			break;
		}
	}

	kfree(fw_msg_buf);
	return ret;
}

static int pd692x0_fw_write_line(struct i2c_client *client,
				 char line[PD692X0_FW_LINE_MAX_SZ],
				 bool last_line)
{
	int ret;

	while(line[0] != 0) {
		ret = i2c_master_send(client, line, sizeof(char));
		if (ret < 0) {
			dev_err(&client->dev,
			"Failed to boot programming mode (%pe)\n", ERR_PTR(ret));
			return FW_UPLOAD_ERR_RW_ERROR;
		}
		line++;
	}

	if (last_line) {
		ret = pd692x0_fw_recv_resp(client, 100, "TP\r\n", sizeof("TP\r\n"));
		if (ret)
			return ret;
	} else {
		ret = pd692x0_fw_recv_resp(client, 100, "T*\r\n", sizeof("T*\r\n"));
		if (ret)
			return ret;
	}

	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err pd692x0_fw_reset(struct i2c_client *client)
{
	struct pd692x0_msg_content buf = {0}, dummy = {0};
	unsigned long timeout;
	char fw_msg_buf[5];
	char cmd[] = "RST";
	int ret;

	ret = i2c_master_send(client, cmd, sizeof(cmd) - sizeof(char));
	if (ret < 0) {
		dev_err(&client->dev,
		"Failed to reset the controller (%pe)\n", ERR_PTR(ret));
		return ret;
	}

	memset(fw_msg_buf, 0, sizeof(fw_msg_buf));
	timeout = msecs_to_jiffies(10000) + jiffies;
	while(true) {
		if (time_is_before_jiffies(timeout))
			return FW_UPLOAD_ERR_TIMEOUT;

		ret = i2c_master_recv(client, (u8 *)&buf, sizeof(struct pd692x0_msg_content));
		if (ret < 0 ||
		    !memcmp(&buf, &dummy, sizeof(struct pd692x0_msg_content)))
			msleep(1);
		else
			break;
	}

	pr_err("RCV \n");
	pd692x0_dump_msg(&buf);

	if (buf.key != 0x03 || buf.echo != 0xff || buf.sub[0] & 0x01) {
		dev_err(&client->dev, "PSE controller error\n");
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	if (buf.sub[0] & 0x02) {
		dev_err(&client->dev, "PSE firmware error. Please update it.\n");
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err pd692x0_fw_prepare(struct fw_upload *fwl,
					     const u8 *data, u32 size)
{
	struct pd692x0_priv *priv = fwl->dd_handle;
	struct i2c_client *client = priv->client;
	enum pd692x0_fw_state last_fw_state;
	char cmd;
	int ret;

	priv->cancel_request = false;
	last_fw_state = priv->fw_state;
pr_err("%s : %d, %d\n", __func__, __LINE__, last_fw_state);

	priv->fw_state = PD692X0_FW_PREPARE;

	/* Enter program mode */
	if (last_fw_state == PD692X0_FW_BROKEN) {
		cmd = 'E';
		ret = i2c_master_send(client, &cmd, sizeof(char));
		if (ret < 0)
			return FW_UPLOAD_ERR_RW_ERROR;

		msleep(10);
		cmd = 'N';
		ret = i2c_master_send(client, &cmd, sizeof(char));
		if (ret < 0)
			return FW_UPLOAD_ERR_RW_ERROR;

		msleep(10);
		cmd = 'T';
		ret = i2c_master_send(client, &cmd, sizeof(char));
		if (ret < 0)
			return FW_UPLOAD_ERR_RW_ERROR;

		msleep(10);
		cmd = 'R';
		ret = i2c_master_send(client, &cmd, sizeof(char));
		if (ret < 0)
			return FW_UPLOAD_ERR_RW_ERROR;

	} else {
		struct pd692x0_msg msg = pd692x0_msg_list[PD692X0_MSG_DOWNLOAD_CMD];
		struct pd692x0_msg_content buf;

		ret = pd692x0_sendrecv_msg(priv, msg, &buf);
		if (ret < 0) {
			dev_err(&client->dev,
			"Failed to enter programming mode (%pe)\n", ERR_PTR(ret));
			return FW_UPLOAD_ERR_RW_ERROR;
		}
	}

	ret = pd692x0_fw_recv_resp(client, 100, "TPE\r\n", sizeof("TPE\r\n"));
	if (ret)
		goto err_out;

	if (priv->cancel_request) {
		ret = FW_UPLOAD_ERR_CANCELED;
		goto err_out;
	}

	return FW_UPLOAD_ERR_NONE;

err_out:
	pd692x0_fw_reset(priv->client);
	priv->fw_state = last_fw_state;
	return ret;
}

static enum fw_upload_err pd692x0_fw_write(struct fw_upload *fwl,
					   const u8 *data, u32 offset,
					   u32 size, u32 *written)
{
	struct pd692x0_priv *priv = fwl->dd_handle;
	struct i2c_client *client = priv->client;
	char line[PD692X0_FW_LINE_MAX_SZ];
	int ret, i;
	char cmd;

	priv->fw_state = PD692X0_FW_WRITE;

	/* Erase */
	cmd = 'E';
	ret = i2c_master_send(client, &cmd, sizeof(char));
	if (ret < 0) {
		dev_err(&client->dev,
		"Failed to boot programming mode (%pe)\n", ERR_PTR(ret));
		return FW_UPLOAD_ERR_RW_ERROR;
	}

	ret = pd692x0_fw_recv_resp(client, 100, "TOE\r\n", sizeof("TOE\r\n"));
	if (ret)
		return ret;

	ret = pd692x0_fw_recv_resp(client, 5000, "TE\r\n", sizeof("TE\r\n"));
	if (ret)
		dev_err(&client->dev,
		"Failed to erase internal memory, however still try to write Firmware\n");

	ret = pd692x0_fw_recv_resp(client, 100, "TPE\r\n", sizeof("TPE\r\n"));
	if (ret)
		dev_err(&client->dev,
		"Failed to erase internal memory, however still try to write Firmware\n");


	if (priv->cancel_request)
		return FW_UPLOAD_ERR_CANCELED;

	/* Program */
	cmd = 'P';
	ret = i2c_master_send(client, &cmd, sizeof(char));
	if (ret < 0) {
		dev_err(&client->dev,
		"Failed to boot programming mode (%pe)\n", ERR_PTR(ret));
		return ret;
	}

	if (priv->cancel_request)
		return FW_UPLOAD_ERR_CANCELED;

	ret = pd692x0_fw_recv_resp(client, 100, "TOP\r\n", sizeof("TOP\r\n"));
	if (ret)
		return ret;

	i = 0;
	while (i < size) {
		ret = pd692x0_fw_get_next_line(data, line);
		if (!ret)
			return FW_UPLOAD_ERR_FW_INVALID;

		i += ret;
		data += ret;
//pr_err("%s : %d i %d size %d line %s\n", __func__, __LINE__, i, size, line);
		if (line[0] == 'S' && line[1] == '0') {
			continue;
		} else if (line[0] == 'S' && line[1] == '7') {
			ret = pd692x0_fw_write_line(client, line, true);
			if (ret)
				return ret;
		} else {
			ret = pd692x0_fw_write_line(client, line, false);
			if (ret)
				return ret;
		}

		if (priv->cancel_request) {
			pd692x0_fw_write_line(client, "S7", true);
			return FW_UPLOAD_ERR_CANCELED;
		}
	}
	*written = i;

	msleep(400);

	return FW_UPLOAD_ERR_NONE;
}

static enum fw_upload_err pd692x0_fw_poll_complete(struct fw_upload *fwl)
{
	struct pd692x0_priv *priv = fwl->dd_handle;
	struct i2c_client *client = priv->client;
	struct pd692x0_msg_ver ver;
	int ret;

	priv->fw_state = PD692X0_FW_COMPLETE;

	ret = pd692x0_fw_reset(client);
	if (ret)
		return ret;

	ver = pd692x0_get_sw_version(priv);
	dev_err(&client->dev, "Software version %d.%02d.%d.%d\n", ver.prod,
		ver.maj_sw_ver, ver.min_sw_ver, ver.pa_sw_ver);

	if (ver.maj_sw_ver != PD692X0_FW_MAJ_VER) {
		dev_err(&client->dev, "Too old firmware version. Please update it\n");
		priv->fw_state = PD692X0_FW_NEED_UPDATE;
		return FW_UPLOAD_ERR_FW_INVALID;
	}

	ret = pd692x0_update_matrix(priv);
	if (ret < 0) {
		dev_err(&client->dev, "Error configuring ports matrix (%pe)\n",
			ERR_PTR(ret));
		return FW_UPLOAD_ERR_HW_ERROR;
	}

	priv->fw_state = PD692X0_FW_OK;

	return FW_UPLOAD_ERR_NONE;
}

static void pd692x0_fw_cancel(struct fw_upload *fwl)
{
	struct pd692x0_priv *priv = fwl->dd_handle;

	priv->cancel_request = true;
}

static void pd692x0_fw_cleanup(struct fw_upload *fwl)
{
	struct pd692x0_priv *priv = fwl->dd_handle;

	switch (priv->fw_state) {
	case PD692X0_FW_WRITE:
		pd692x0_fw_reset(priv->client);
		fallthrough;
	case PD692X0_FW_COMPLETE:
		priv->fw_state = PD692X0_FW_BROKEN;
		break;
	default:
		break;
	}
}

static const struct fw_upload_ops pd692x0_fw_ops = {
	.prepare = pd692x0_fw_prepare,
	.write = pd692x0_fw_write,
	.poll_complete = pd692x0_fw_poll_complete,
	.cancel = pd692x0_fw_cancel,
	.cleanup = pd692x0_fw_cleanup,
};

static const struct of_device_id pd692x0_of_match[] = {
	{ .compatible = "microchip,pd69200", .data = (void *) PD69200_BT_PROD_VER},
	{ .compatible = "microchip,pd69210", .data = (void *) PD69210_BT_PROD_VER},
	{ .compatible = "microchip,pd69220", .data = (void *) PD69220_BT_PROD_VER},
	{ },
};
MODULE_DEVICE_TABLE(of, pd692x0_of_match);

static int pd692x0_i2c_probe(struct i2c_client *client)
{
	struct pd692x0_msg_content buf = {0};
	struct device *dev = &client->dev;
	const struct of_device_id *match;
	struct pd692x0_msg_ver ver;
	struct pd692x0_priv *priv;
	struct fw_upload *fwl;
	int ret;

	if (!i2c_check_functionality(client->adapter, I2C_FUNC_I2C)) {
		dev_err(dev, "i2c check functionality failed\n");
		return -ENXIO;
	}

	match = i2c_of_match_device(pd692x0_of_match, client);
	if (!match)
		return -ENODEV;

	priv = devm_kzalloc(dev, sizeof(*priv), GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	priv->client = client;
	i2c_set_clientdata(client, priv);

	priv->pse_prod_num = (unsigned long)match->data;
	priv->pcdev.owner = THIS_MODULE;
	priv->pcdev.ops = &pd692x0_ops;
	priv->pcdev.dev = dev;
	priv->pcdev.types = PSE_POE;
	priv->pcdev.of_pse_n_cells = 1;
	priv->pcdev.nr_lines = PD692X0_MAX_PORTS;
	ret = devm_pse_controller_register(dev, &priv->pcdev);
	if (ret) {
		dev_err(dev, "failed to register PSE controller (%pe)\n",
			ERR_PTR(ret));
		return ret;
	}

	fwl = firmware_upload_register(THIS_MODULE, dev, dev_name(dev),
				       &pd692x0_fw_ops, priv);
	if (IS_ERR(fwl)) {
		dev_err(dev, "Firmware Upload driver failed to start\n");
		ret = PTR_ERR(fwl);
		return ret;
	}
	priv->fwl = fwl;

	ret = i2c_master_recv(client, (u8 *)&buf, sizeof(struct pd692x0_msg_content));
	if (ret != sizeof(struct pd692x0_msg_content)) {
		ret = -EIO;
		goto err_fw_unregister;
	}

	pr_err("RCV \n");
	pd692x0_dump_msg(&buf);

	if (buf.key != 0x03 || buf.echo != 0xff || buf.sub[0] & 0x01) {
		dev_err(dev, "PSE controller error\n");
		ret = -EIO;
		goto err_fw_unregister;
	}

	if (buf.sub[0] & 0x02) {
		dev_err(dev, "PSE firmware error. Please update it.\n");
		priv->fw_state = PD692X0_FW_BROKEN;
		return 0;
	}

	ver = pd692x0_get_sw_version(priv);

	dev_err(&client->dev, "Software version %d.%02d.%d.%d\n", ver.prod,
		ver.maj_sw_ver, ver.min_sw_ver, ver.pa_sw_ver);

	if (ver.maj_sw_ver != PD692X0_FW_MAJ_VER) {
		dev_err(dev, "Too old firmware version. Please update it\n");
		priv->fw_state = PD692X0_FW_NEED_UPDATE;
		return 0;
	}

	ret = pd692x0_update_matrix(priv);
	if (ret < 0) {
		dev_err(dev, "Error configuring ports matrix (%pe)\n",
			ERR_PTR(ret));
		goto err_fw_unregister;
	}

	priv->fw_state = PD692X0_FW_OK;

	return 0;

err_fw_unregister:
	firmware_upload_unregister(priv->fwl);
	return ret;
}

void pd692x0_i2c_remove(struct i2c_client *client)
{
	struct pd692x0_priv *priv = i2c_get_clientdata(client);

	firmware_upload_unregister(priv->fwl);
}

static const struct i2c_device_id pd692x0_id[] = {
	{ PD692X0_PSE_NAME, 0 },
	{ },
};
MODULE_DEVICE_TABLE(i2c, pd692x0_id);

static struct i2c_driver pd692x0_driver = {
	.probe		= pd692x0_i2c_probe,
	.remove		= pd692x0_i2c_remove,
	.id_table	= pd692x0_id,
	.driver		= {
		.name		= PD692X0_PSE_NAME,
		.of_match_table = of_match_ptr(pd692x0_of_match),
	},
};
module_i2c_driver(pd692x0_driver);

MODULE_AUTHOR("Kory Maincent <kory.maincent@bootlin.com>");
MODULE_DESCRIPTION("Microchip PD692x0 PoE PSE Controller driver");
MODULE_LICENSE("GPL v2");
