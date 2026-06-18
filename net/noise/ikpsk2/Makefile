# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Noise IKpsk2 cryptographic framework
#
CONFIG_NOISE_IKPSK2 ?= m
obj-$(CONFIG_NOISE_IKPSK2) += noise_ikpsk2.o

noise_ikpsk2-y := noise_main.o noise_crypto.o handshake.o noise_transport.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean
