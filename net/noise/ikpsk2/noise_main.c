/*  
 *  hello-2.c - Demonstrating the module_init() and module_exit() macros.
 *  This is preferred over using init_module() and cleanup_module().
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for the macros */
#include "handshake.h"

static int __init noise_init(void)
{
	printk(KERN_INFO "Custom module loaded with crypto functions ready.\n");
	ikpsk2_noise_init();
	printk(KERN_INFO "IKpsk2 init ok.\n");
	return 0;
}

static void __exit noise_exit(void)
{
	printk(KERN_INFO "Custom module unloaded.\n");
}

module_init(noise_init);
module_exit(noise_exit);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("kernel module, crypto compilation module");
MODULE_AUTHOR("Axel Biegalski");
MODULE_VERSION("1.0.1");
