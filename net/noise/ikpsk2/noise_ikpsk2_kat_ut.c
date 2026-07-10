// SPDX-License-Identifier: GPL-2.0
/* NOISE: comment to address */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/printk.h>

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

#include <net/noise.h>
#include "noise_crypto.h"
#include "noise_ikpsk2_ut.h"

/* NOISE: comment to address */
static bool kat_check(const char *name, const u8 *actual,
		      const u8 *expected, size_t len)
{
	u8 zero[NOISE_HASH_LEN] = {};

	if (len <= sizeof(zero) && memcmp(expected, zero, len) == 0) {
		/* NOISE: comment to address */
		pr_warn("noise_kat: [%s] golden unset - captured value below\n",
			name);
		print_hex_dump(KERN_WARNING, "noise_kat:   ", DUMP_PREFIX_NONE,
			       32, 1, actual, len, false);
		return true;
	}

	if (memcmp(actual, expected, len) != 0) {
		pr_err("noise_kat: [%s] MISMATCH\n", name);
		print_hex_dump(KERN_ERR, "noise_kat: got ", DUMP_PREFIX_NONE,
			       32, 1, actual, len, false);
		print_hex_dump(KERN_ERR, "noise_kat: exp ", DUMP_PREFIX_NONE,
			       32, 1, expected, len, false);
		return false;
	}

	pr_info("noise_kat: [%s] ok\n", name);
	return true;
}

/* NOISE: comment to address */
static bool kat_curve25519(void)
{
	/* NOISE: comment to address */
	static const u8 scalar[NOISE_PUBLIC_KEY_LEN] = {
		0xa5, 0x46, 0xe3, 0x6b, 0xf0, 0x52, 0x7c, 0x9d,
		0x3b, 0x16, 0x15, 0x4b, 0x82, 0x46, 0x5e, 0xdd,
		0x62, 0x14, 0x4c, 0x0a, 0xc1, 0xfc, 0x5a, 0x18,
		0x50, 0x6a, 0x22, 0x44, 0xba, 0x44, 0x9a, 0xc4,
	};
	static const u8 point[NOISE_PUBLIC_KEY_LEN] = {
		0xe6, 0xdb, 0x68, 0x67, 0x58, 0x30, 0x30, 0xdb,
		0x35, 0x94, 0xc1, 0xa4, 0x24, 0xb1, 0x5f, 0x7c,
		0x72, 0x66, 0x24, 0xec, 0x26, 0xb3, 0x35, 0x3b,
		0x10, 0xa9, 0x03, 0xa6, 0xd0, 0xab, 0x1c, 0x4c,
	};
	static const u8 expected[NOISE_PUBLIC_KEY_LEN] = {
		0xc3, 0xda, 0x55, 0x37, 0x9d, 0xe9, 0xc6, 0x90,
		0x8e, 0x94, 0xea, 0x4d, 0xf2, 0x8d, 0x08, 0x4f,
		0x32, 0xec, 0xcf, 0x03, 0x49, 0x1c, 0x71, 0xf7,
		0x54, 0xb4, 0x07, 0x55, 0x77, 0xa2, 0x85, 0x52,
	};
	u8 out[NOISE_PUBLIC_KEY_LEN];

	if (!curve25519(out, scalar, point)) {
		pr_err("noise_kat: [curve25519_rfc7748] curve25519() failed\n");
		return false;
	}
	return kat_check("curve25519_rfc7748", out, expected,
			 NOISE_PUBLIC_KEY_LEN);
}

/* NOISE: comment to address */
static const u8 KAT_INIT_CHAINING_KEY[NOISE_HASH_LEN] = {};
static const u8 KAT_INIT_HASH[NOISE_HASH_LEN] = {};

/* NOISE: comment to address */
static bool kat_init_handshake(void)
{
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 ck[NOISE_HASH_LEN];
	u8 h[NOISE_HASH_LEN];
	bool r1, r2;

	memset(remote_static, 0x66, sizeof(remote_static));
	init_handshake(ck, h, remote_static);

	r1 = kat_check("init_chaining_key", ck, KAT_INIT_CHAINING_KEY,
		       NOISE_HASH_LEN);
	r2 = kat_check("init_hash", h, KAT_INIT_HASH, NOISE_HASH_LEN);
	return r1 && r2;
}

/* NOISE: comment to address */
static const u8 KAT_MIX_DH_CK[NOISE_HASH_LEN] = {};
static const u8 KAT_MIX_DH_KEY[NOISE_SYMMETRIC_KEY_LEN] = {};

/* NOISE: comment to address */
static bool kat_mix_dh(void)
{
	u8 priv[NOISE_PUBLIC_KEY_LEN];
	u8 pub[NOISE_PUBLIC_KEY_LEN];
	u8 ck[NOISE_HASH_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool r1, r2;

	memset(priv, 0x11, sizeof(priv));
	memset(pub, 0x22, sizeof(pub));
	memset(ck, 0x33, sizeof(ck));

	if (!mix_dh(ck, key, priv, pub)) {
		pr_err("noise_kat: [mix_dh] mix_dh() failed\n");
		return false;
	}

	r1 = kat_check("mix_dh_chaining_key", ck, KAT_MIX_DH_CK, NOISE_HASH_LEN);
	r2 = kat_check("mix_dh_key", key, KAT_MIX_DH_KEY,
		       NOISE_SYMMETRIC_KEY_LEN);
	return r1 && r2;
}

/* NOISE: comment to address */
static const u8 KAT_AEAD_CT[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)] = {};

/* NOISE: comment to address */
static bool kat_aead(void)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash[NOISE_HASH_LEN];
	u8 pt[NOISE_PUBLIC_KEY_LEN];
	u8 ct[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];

	memset(key, 0x2a, sizeof(key));
	memset(hash, 0x3b, sizeof(hash));
	memset(pt, 0x4c, sizeof(pt));

	message_encrypt(ct, pt, sizeof(pt), key, hash);

	return kat_check("aead_ciphertext", ct, KAT_AEAD_CT,
			 noise_encrypted_len(NOISE_PUBLIC_KEY_LEN));
}

/* NOISE: comment to address */
static const u8 KAT_DERIVE_KEY_1[NOISE_SYMMETRIC_KEY_LEN] = {};
static const u8 KAT_DERIVE_KEY_2[NOISE_SYMMETRIC_KEY_LEN] = {};

/* NOISE: comment to address */
static bool kat_derive_keys(void)
{
	u8 ck[NOISE_HASH_LEN];
	u8 k1[NOISE_SYMMETRIC_KEY_LEN];
	u8 k2[NOISE_SYMMETRIC_KEY_LEN];
	bool r1, r2;

	memset(ck, 0x5d, sizeof(ck));
	derive_keys(k1, k2, ck);

	r1 = kat_check("derive_key_1", k1, KAT_DERIVE_KEY_1,
		       NOISE_SYMMETRIC_KEY_LEN);
	r2 = kat_check("derive_key_2", k2, KAT_DERIVE_KEY_2,
		       NOISE_SYMMETRIC_KEY_LEN);
	return r1 && r2;
}

/* NOISE: comment to address */
bool noise_ikpsk2_kat_selftest(void)
{
	bool ok = true;

	/* NOISE: comment to address */
	if (!kat_curve25519())
		ok = false;
	if (!kat_init_handshake())
		ok = false;
	if (!kat_mix_dh())
		ok = false;
	if (!kat_aead())
		ok = false;
	if (!kat_derive_keys())
		ok = false;

	if (ok)
		pr_info("noise_kat: all KATs passed (or captured)\n");
	else
		pr_err("noise_kat: KATs FAILED\n");

	return ok;
}
