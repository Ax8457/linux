// SPDX-License-Identifier: GPL-2.0
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Module init: prepares the IKpsk2 initial chaining key / hash.
 *
 *	Axel Biegalski - HWU MSc project
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
/* NOISE is now available in linux kernel */
#include <net/noise.h>

static int __init noise_init(void)
{
	int ret;

	printk(KERN_INFO "Custom module loaded with crypto functions ready.\n");
	ikpsk2_noise_init();

	/* keyring holding the long-term secrets (PSKs, static private keys) */
	ret = ikpsk2_keyring_init();
	if (ret) {
		printk(KERN_ERR "IKpsk2 keyring init failed (%d).\n", ret);
		return ret;
	}

	printk(KERN_INFO "IKpsk2 init ok.\n");
	return 0;
}

static void __exit noise_exit(void)
{
	ikpsk2_keyring_exit();
	printk(KERN_INFO "Custom module unloaded.\n");
}

module_init(noise_init);
module_exit(noise_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("kernel module, crypto compilation module");
MODULE_AUTHOR("Axel Biegalski");
MODULE_VERSION("1.0.1");
