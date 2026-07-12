# SPDX-License-Identifier: GPL-2.0-only
#
# Makefile for the Noise IKpsk2 cryptographic framework
#
obj-$(CONFIG_NOISE_IKPSK2) += noise_ikpsk2.o

# NOISE: comment to address
# Warn (don't fail) if any function in this module uses > 512 bytes of stack.
# Scoped to this directory only, unlike the global CONFIG_FRAME_WARN.
# Bare -Wno-error keeps CONFIG_WERROR from turning the warning into a build
# error (this GCC rejects the finer-grained -Wno-error=frame-larger-than).
ccflags-y += -Wframe-larger-than=512
ccflags-y += -Wno-error

noise_ikpsk2-y := noise_main.o noise_crypto.o handshake.o noise_transport.o noise_ulp.o noise_keys.o cookie.o ratelimiter.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_ut.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_handshake_ut.o
noise_ikpsk2-$(CONFIG_NOISE_IKPSK2_SELFTEST) += noise_ikpsk2_kat_ut.o
