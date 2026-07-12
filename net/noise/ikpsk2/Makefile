# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Noise IKpsk2 cryptographic framework
#
obj-$(CONFIG_NOISE_IKPSK2) += noise_ikpsk2.o

# NOISE: comment to address
ccflags-y += -Wframe-larger-than=512
ccflags-y += -Wno-error=frame-larger-than

noise_ikpsk2-y := noise_main.o noise_crypto.o handshake.o noise_transport.o noise_ulp.o noise_keys.o cookie.o ratelimiter.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_ut.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_handshake_ut.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_kat_ut.o
