/******************************************************************************
 *
 * Copyright(c) 2009-2012  Realtek Corporation.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * The full GNU General Public License is included in this distribution in the
 * file called LICENSE.
 *
 * Contact Information:
 * wlanfae <wlanfae@realtek.com>
 * Realtek Corporation, No. 2, Innovation Road II, Hsinchu Science Park,
 * Hsinchu 300, Taiwan.
 *
 * Larry Finger <Larry.Finger@lwfinger.net>
 *****************************************************************************/

#include "wifi.h"
#include "cam.h"

#include <linux/moduleparam.h>
#include <linux/vmalloc.h>

#ifdef CONFIG_RTLWIFI_DEBUG
void _rtl_dbg_trace(struct rtl_priv *rtlpriv, u64 comp, int level,
		    const char *fmt, ...)
{
	if (unlikely((comp & rtlpriv->cfg->mod_params->debug_mask) &&
		     (level <= rtlpriv->cfg->mod_params->debug_level))) {
		struct va_format vaf;
		va_list args;

		va_start(args, fmt);

		vaf.fmt = fmt;
		vaf.va = &args;

		pr_info(":<%lx> %pV", in_interrupt(), &vaf);

		va_end(args);
	}
}
EXPORT_SYMBOL_GPL(_rtl_dbg_trace);

void _rtl_dbg_print(struct rtl_priv *rtlpriv, u64 comp, int level,
		    const char *fmt, ...)
{
	if (unlikely((comp & rtlpriv->cfg->mod_params->debug_mask) &&
		     (level <= rtlpriv->cfg->mod_params->debug_level))) {
		struct va_format vaf;
		va_list args;

		va_start(args, fmt);

		vaf.fmt = fmt;
		vaf.va = &args;

		pr_info("%pV", &vaf);

		va_end(args);
	}
}
EXPORT_SYMBOL_GPL(_rtl_dbg_print);

void _rtl_dbg_print_data(struct rtl_priv *rtlpriv, u64 comp, int level,
			 const char *titlestring,
			 const void *hexdata, int hexdatalen)
{
	if (unlikely(((comp) & rtlpriv->cfg->mod_params->debug_mask) &&
		     ((level) <= rtlpriv->cfg->mod_params->debug_level))) {
		pr_info("In process \"%s\" (pid %i): %s\n",
			current->comm, current->pid, titlestring);
		print_hex_dump_bytes("", DUMP_PREFIX_NONE,
				     hexdata, hexdatalen);
	}
}
EXPORT_SYMBOL_GPL(_rtl_dbg_print_data);

static struct dentry *debugfs_topdir;

#define RTL_DEBUG_IMPL_GET(name, cb, cb_val)			\
static int rtl_debug_get_ ##name(struct seq_file *m, void *v)	\
{								\
	return cb(m, v, cb_val);				\
}

#define RTL_DEBUG_IMPL_OPEN(name)					       \
static int dl_debug_open_ ##name(struct inode *inode, struct file *file)       \
{									       \
	return single_open(file, rtl_debug_get_ ##name, inode->i_private);     \
}

#define RTL_DEBUG_IMPL_FUNC(name, cb, cb_val)			\
	RTL_DEBUG_IMPL_GET(name, cb, cb_val)			\
	RTL_DEBUG_IMPL_OPEN(name)

#define RTL_DEBUG_FILE_OPS(name)				\
static const struct file_operations file_ops_ ##name = {	\
	.open = dl_debug_open_ ##name,				\
	.read = seq_read,					\
	.llseek = seq_lseek,					\
	.release = seq_release,					\
};

static int _rtl_debug_get_mac_page_x(struct seq_file *m, void *v, int page)
{
	struct ieee80211_hw *hw = m->private;
	struct rtl_priv *rtlpriv = rtl_priv(hw);
	int i, n;
	int max = 0xff;

	for (n = 0; n <= max; ) {
		seq_printf(m, "\n%8.8x  ", n + page);
		for (i = 0; i < 4 && n <= max; i++, n += 4)
			seq_printf(m, "%8.8x    ",
				   rtl_read_dword(rtlpriv, (page | n)));
	}
	seq_puts(m, "\n");
	return 0;
}

#define RTL_DEBUG_IMPL_MAC_SERIES(page, addr)				  \
	RTL_DEBUG_IMPL_FUNC(mac_ ##page, _rtl_debug_get_mac_page_x, addr) \
	RTL_DEBUG_FILE_OPS(mac_ ##page)

RTL_DEBUG_IMPL_MAC_SERIES(0, 0x0000);
RTL_DEBUG_IMPL_MAC_SERIES(1, 0x0100);
RTL_DEBUG_IMPL_MAC_SERIES(2, 0x0200);
RTL_DEBUG_IMPL_MAC_SERIES(3, 0x0300);
RTL_DEBUG_IMPL_MAC_SERIES(4, 0x0400);
RTL_DEBUG_IMPL_MAC_SERIES(5, 0x0500);
RTL_DEBUG_IMPL_MAC_SERIES(6, 0x0600);
RTL_DEBUG_IMPL_MAC_SERIES(7, 0x0700);
RTL_DEBUG_IMPL_MAC_SERIES(10, 0x1000);
RTL_DEBUG_IMPL_MAC_SERIES(11, 0x1100);
RTL_DEBUG_IMPL_MAC_SERIES(12, 0x1200);
RTL_DEBUG_IMPL_MAC_SERIES(13, 0x1300);
RTL_DEBUG_IMPL_MAC_SERIES(14, 0x1400);
RTL_DEBUG_IMPL_MAC_SERIES(15, 0x1500);
RTL_DEBUG_IMPL_MAC_SERIES(16, 0x1600);
RTL_DEBUG_IMPL_MAC_SERIES(17, 0x1700);

static int _rtl_debug_get_bb_page_x(struct seq_file *m, void *v, int page)
{
	struct ieee80211_hw *hw = m->private;
	int i, n;
	int max = 0xff;

	for (n = 0; n <= max; ) {
		seq_printf(m, "\n%8.8x  ", n + page);
		for (i = 0; i < 4 && n <= max; i++, n += 4)
			seq_printf(m, "%8.8x    ",
				   rtl_get_bbreg(hw, (page | n), 0xffffffff));
	}
	seq_puts(m, "\n");
	return 0;
}

#define RTL_DEBUG_IMPL_BB_SERIES(page, addr)				\
	RTL_DEBUG_IMPL_FUNC(bb_ ##page, _rtl_debug_get_bb_page_x, addr)	\
	RTL_DEBUG_FILE_OPS(bb_ ##page)

RTL_DEBUG_IMPL_BB_SERIES(8, 0x0800);
RTL_DEBUG_IMPL_BB_SERIES(9, 0x0900);
RTL_DEBUG_IMPL_BB_SERIES(a, 0x0a00);
RTL_DEBUG_IMPL_BB_SERIES(b, 0x0b00);
RTL_DEBUG_IMPL_BB_SERIES(c, 0x0c00);
RTL_DEBUG_IMPL_BB_SERIES(d, 0x0d00);
RTL_DEBUG_IMPL_BB_SERIES(e, 0x0e00);
RTL_DEBUG_IMPL_BB_SERIES(f, 0x0f00);
RTL_DEBUG_IMPL_BB_SERIES(18, 0x1800);
RTL_DEBUG_IMPL_BB_SERIES(19, 0x1900);
RTL_DEBUG_IMPL_BB_SERIES(1a, 0x1a00);
RTL_DEBUG_IMPL_BB_SERIES(1b, 0x1b00);
RTL_DEBUG_IMPL_BB_SERIES(1c, 0x1c00);
RTL_DEBUG_IMPL_BB_SERIES(1d, 0x1d00);
RTL_DEBUG_IMPL_BB_SERIES(1e, 0x1e00);
RTL_DEBUG_IMPL_BB_SERIES(1f, 0x1f00);

static int _rtl_debug_get_reg_rf_x(struct seq_file *m, void *v,
				   enum radio_path rfpath)
{
	struct ieee80211_hw *hw = m->private;
	struct rtl_priv *rtlpriv = rtl_priv(hw);
	struct rtl_hal *rtlhal = rtl_hal(rtlpriv);
	int i, n;
	int max = 0x40;

	if (rtlhal->hw_type == HARDWARE_TYPE_RTL8822BE)
		max = 0xff;

	for (n = 0; n <= max; ) {
		seq_printf(m, "\n%8.8x  ", n);
		for (i = 0; i < 4 && n <= max; n += 1, i++)
			seq_printf(m, "%8.8x    ",
				   rtl_get_rfreg(hw, rfpath, n, 0xffffffff));
	}
	seq_puts(m, "\n");
	return 0;
}

#define RTL_DEBUG_IMPL_RF_SERIES(page, path)				\
	RTL_DEBUG_IMPL_FUNC(rf_ ##page, _rtl_debug_get_reg_rf_x, path)	\
	RTL_DEBUG_FILE_OPS(rf_ ##page)

RTL_DEBUG_IMPL_RF_SERIES(a, RF90_PATH_A);
RTL_DEBUG_IMPL_RF_SERIES(b, RF90_PATH_B);

static int _rtl_debug_get_cam_register_x(struct seq_file *m, void *v, int start)
{
	struct ieee80211_hw *hw = m->private;
	struct rtl_priv *rtlpriv = rtl_priv(hw);
	u32 target_cmd = 0;
	u32 target_val = 0;
	u8 entry_i = 0;
	u32 ulstatus;
	int i = 100, j = 0;
	int end = (start + 11 > TOTAL_CAM_ENTRY ? TOTAL_CAM_ENTRY : start + 11);

	/* This dump the current register page */
	seq_printf(m,
		   "\n#################### SECURITY CAM (%d-%d) ##################\n",
		   start, end - 1);

	for (j = start; j < end; j++) {
		seq_printf(m, "\nD:  %2x > ", j);
		for (entry_i = 0; entry_i < CAM_CONTENT_COUNT; entry_i++) {
			/* polling bit, and No Write enable, and address  */
			target_cmd = entry_i + CAM_CONTENT_COUNT * j;
			target_cmd = target_cmd | BIT(31);

			/* Check polling bit is clear */
			while ((i--) >= 0) {
				ulstatus = rtl_read_dword(rtlpriv,
						rtlpriv->cfg->maps[RWCAM]);
				if (ulstatus & BIT(31))
					continue;
				else
					break;
			}

			rtl_write_dword(rtlpriv, rtlpriv->cfg->maps[RWCAM],
					target_cmd);
			target_val = rtl_read_dword(rtlpriv,
						    rtlpriv->cfg->maps[RCAMO]);
			seq_printf(m, "%8.8x ", target_val);
		}
	}
	seq_puts(m, "\n");
	return 0;
}

#define RTL_DEBUG_IMPL_CAM_SERIES(page, start)				       \
	RTL_DEBUG_IMPL_FUNC(cam_ ##page, _rtl_debug_get_cam_register_x, start) \
	RTL_DEBUG_FILE_OPS(cam_ ##page)

RTL_DEBUG_IMPL_CAM_SERIES(1, 0);
RTL_DEBUG_IMPL_CAM_SERIES(2, 11);
RTL_DEBUG_IMPL_CAM_SERIES(3, 22);

static int rtl_debug_get_btcoex(struct seq_file *m, void *v)
{
	struct ieee80211_hw *hw = m->private;
	struct rtl_priv *rtlpriv = rtl_priv(hw);
	u8 *buff;
	u32 size = 30 * 100;
	int n;

	buff = kzalloc(size, GFP_KERNEL);

	if (!buff)
		return 0;

	if (rtlpriv->cfg->ops->get_btc_status())
		rtlpriv->btcoexist.btc_ops->btc_display_bt_coex_info(buff,
								     size);

	n = strlen(buff);

	buff[n++] = '\n';
	buff[n++] = '\0';

	seq_write(m, buff, n);

	return 0;
}

RTL_DEBUG_IMPL_OPEN(btcoex);
RTL_DEBUG_FILE_OPS(btcoex);

static ssize_t rtl_debugfs_set_write_reg(struct file *filp,
					 const char __user *buffer,
					 size_t count, loff_t *loff)
{
	struct ieee80211_hw *hw = filp->private_data;
	struct rtl_priv *rtlpriv = rtl_priv(hw);

	char tmp[32];
	u32 addr, val, len;

	if (count < 3) {
		/*printk("argument size is less than 3\n");*/
		return -EFAULT;
	}

	if (buffer && !copy_from_user(tmp, buffer, sizeof(tmp))) {
		int num = sscanf(tmp, "%x %x %x", &addr, &val, &len);

		if (num !=  3) {
			/*printk("invalid write_reg parameter!\n");*/
			return count;
		}

		switch (len) {
		case 1:
			rtl_write_byte(rtlpriv, addr, (u8)val);
			break;
		case 2:
			rtl_write_word(rtlpriv, addr, (u16)val);
			break;
		case 4:
			rtl_write_dword(rtlpriv, addr, val);
			break;
		default:
			/*printk("error write length=%d", len);*/
			break;
		}
	}

	return count;
}

static int rtl_debugfs_open(struct inode *inode, struct file *filp)
{
	filp->private_data = inode->i_private;

	return 0;
}

static int rtl_debugfs_close(struct inode *inode, struct file *filp)
{
	return 0;
}

static const struct file_operations file_ops_write_reg = {
	.owner = THIS_MODULE,
	.write = rtl_debugfs_set_write_reg,
	.open = rtl_debugfs_open,
	.release = rtl_debugfs_close,
};

static ssize_t rtl_debugfs_phydm_cmd(struct file *filp,
				     const char __user *buffer, size_t count,
				     loff_t *loff)
{
	struct ieee80211_hw *hw = filp->private_data;
	struct rtl_priv *rtlpriv = rtl_priv(hw);

	char tmp[64];

	if (!rtlpriv->dbg.msg_buf)
		return -ENOMEM;

	if (!rtlpriv->phydm.ops)
		return -EFAULT;

	if (buffer && !copy_from_user(tmp, buffer, sizeof(tmp))) {
		tmp[count] = '\0';

		rtlpriv->phydm.ops->phydm_debug_cmd(rtlpriv, tmp, count,
						    rtlpriv->dbg.msg_buf,
						    80 * 25);
	}

	return count;
}

static int rtl_debug_get_phydm_cmd(struct seq_file *m, void *v)
{
	struct ieee80211_hw *hw = m->private;
	struct rtl_priv *rtlpriv = rtl_priv(hw);

	if (rtlpriv->dbg.msg_buf)
		seq_puts(m, rtlpriv->dbg.msg_buf);

	return 0;
}

static int rtl_debugfs_open_rw(struct inode *inode, struct file *filp)
{
	if (filp->f_mode & FMODE_READ)
		single_open(filp, rtl_debug_get_phydm_cmd, inode->i_private);
	else
		filp->private_data = inode->i_private;

	return 0;
}

static int rtl_debugfs_close_rw(struct inode *inode, struct file *filp)
{
	if (filp->f_mode == FMODE_READ)
		seq_release(inode, filp);

	return 0;
}

static const struct file_operations file_ops_phydm_cmd = {
	.owner = THIS_MODULE,
	.open = rtl_debugfs_open_rw,
	.release = rtl_debugfs_close_rw,
	.read = seq_read,
	.llseek = seq_lseek,
	.write = rtl_debugfs_phydm_cmd,
};

#define RTL_DEBUGFS_ADD_CORE(name, mode)				\
	do {								\
		if (!debugfs_create_file(#name, mode,	\
					 parent, hw, &file_ops_ ##name))  \
			pr_err("Unable to initialize debugfs:%s/%s\n",	\
			       rtlpriv->dbg.debugfs_name,		\
			       #name);					\
	} while (0)

#define RTL_DEBUGFS_ADD(name)	RTL_DEBUGFS_ADD_CORE(name, S_IFREG | S_IRUGO)
#define RTL_DEBUGFS_ADD_W(name)	RTL_DEBUGFS_ADD_CORE(name, S_IFREG | S_IWUGO)
#define RTL_DEBUGFS_ADD_RW(name)					\
	RTL_DEBUGFS_ADD_CORE(name, S_IFREG | S_IWUGO | S_IRUGO)

void rtl_debug_add_one(struct ieee80211_hw *hw)
{
	struct rtl_priv *rtlpriv = rtl_priv(hw);
	struct rtl_efuse *rtlefuse = rtl_efuse(rtl_priv(hw));
	struct dentry *parent;

	rtlpriv->dbg.msg_buf = vzalloc(80 * 25);

	snprintf(rtlpriv->dbg.debugfs_name, 18, "%02x-%02x-%02x-%02x-%02x-%02x",
		 rtlefuse->dev_addr[0], rtlefuse->dev_addr[1],
		 rtlefuse->dev_addr[2], rtlefuse->dev_addr[3],
		 rtlefuse->dev_addr[4], rtlefuse->dev_addr[5]);

	rtlpriv->dbg.debugfs_dir =
		debugfs_create_dir(rtlpriv->dbg.debugfs_name, debugfs_topdir);
	if (!rtlpriv->dbg.debugfs_dir) {
		pr_err("Unable to init debugfs:/%s/%s\n", rtlpriv->cfg->name,
		       rtlpriv->dbg.debugfs_name);
		return;
	}

	parent = rtlpriv->dbg.debugfs_dir;

	RTL_DEBUGFS_ADD(mac_0);
	RTL_DEBUGFS_ADD(mac_1);
	RTL_DEBUGFS_ADD(mac_2);
	RTL_DEBUGFS_ADD(mac_3);
	RTL_DEBUGFS_ADD(mac_4);
	RTL_DEBUGFS_ADD(mac_5);
	RTL_DEBUGFS_ADD(mac_6);
	RTL_DEBUGFS_ADD(mac_7);
	RTL_DEBUGFS_ADD(bb_8);
	RTL_DEBUGFS_ADD(bb_9);
	RTL_DEBUGFS_ADD(bb_a);
	RTL_DEBUGFS_ADD(bb_b);
	RTL_DEBUGFS_ADD(bb_c);
	RTL_DEBUGFS_ADD(bb_d);
	RTL_DEBUGFS_ADD(bb_e);
	RTL_DEBUGFS_ADD(bb_f);
	RTL_DEBUGFS_ADD(mac_10);
	RTL_DEBUGFS_ADD(mac_11);
	RTL_DEBUGFS_ADD(mac_12);
	RTL_DEBUGFS_ADD(mac_13);
	RTL_DEBUGFS_ADD(mac_14);
	RTL_DEBUGFS_ADD(mac_15);
	RTL_DEBUGFS_ADD(mac_16);
	RTL_DEBUGFS_ADD(mac_17);
	RTL_DEBUGFS_ADD(bb_18);
	RTL_DEBUGFS_ADD(bb_19);
	RTL_DEBUGFS_ADD(bb_1a);
	RTL_DEBUGFS_ADD(bb_1b);
	RTL_DEBUGFS_ADD(bb_1c);
	RTL_DEBUGFS_ADD(bb_1d);
	RTL_DEBUGFS_ADD(bb_1e);
	RTL_DEBUGFS_ADD(bb_1f);
	RTL_DEBUGFS_ADD(rf_a);
	RTL_DEBUGFS_ADD(rf_b);

	RTL_DEBUGFS_ADD(cam_1);
	RTL_DEBUGFS_ADD(cam_2);
	RTL_DEBUGFS_ADD(cam_3);

	RTL_DEBUGFS_ADD(btcoex);

	RTL_DEBUGFS_ADD_W(write_reg);

	RTL_DEBUGFS_ADD_RW(phydm_cmd);
}
EXPORT_SYMBOL_GPL(rtl_debug_add_one);

void rtl_debug_remove_one(struct ieee80211_hw *hw)
{
	struct rtl_priv *rtlpriv = rtl_priv(hw);

	debugfs_remove_recursive(rtlpriv->dbg.debugfs_dir);
	rtlpriv->dbg.debugfs_dir = NULL;

	vfree(rtlpriv->dbg.msg_buf);
}
EXPORT_SYMBOL_GPL(rtl_debug_remove_one);

void rtl_debugfs_add_topdir(void)
{
	debugfs_topdir = debugfs_create_dir("rtlwifi", NULL);
}

void rtl_debugfs_remove_topdir(void)
{
	debugfs_remove_recursive(debugfs_topdir);
}

#endif
