// SPDX-License-Identifier: GPL-2.0
/* NOISE: comment to address */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/printk.h>

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

#include <net/noise.h>
#include "noise_crypto.h"
#include "noise_ikpsk2_ut.h"

/* NOISE: comment to address */
#define NOISE_UT_ASSERT(cond)						\
	do {								\
		if (!(cond)) {						\
			pr_err("noise_ut: FAILED: %s (%s:%d)\n",		\
			       #cond, __func__, __LINE__);		\
			return false;					\
		}							\
	} while (0)

/* NOISE: comment to address */
static bool ut_keypair(u8 priv[NOISE_PUBLIC_KEY_LEN],
		       u8 pub[NOISE_PUBLIC_KEY_LEN])
{
	curve25519_generate_secret(priv);
	return curve25519_generate_public(pub, priv);
}

/* NOISE: comment to address */
static bool ut_dh_symmetry(void)
{
	u8 a_priv[NOISE_PUBLIC_KEY_LEN], a_pub[NOISE_PUBLIC_KEY_LEN];
	u8 b_priv[NOISE_PUBLIC_KEY_LEN], b_pub[NOISE_PUBLIC_KEY_LEN];
	u8 s1[NOISE_PUBLIC_KEY_LEN], s2[NOISE_PUBLIC_KEY_LEN];

	NOISE_UT_ASSERT(ut_keypair(a_priv, a_pub));
	NOISE_UT_ASSERT(ut_keypair(b_priv, b_pub));

	NOISE_UT_ASSERT(curve25519(s1, a_priv, b_pub));
	NOISE_UT_ASSERT(curve25519(s2, b_priv, a_pub));

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(s1, s2, NOISE_PUBLIC_KEY_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_mix_dh_converges(void)
{
	u8 a_priv[NOISE_PUBLIC_KEY_LEN], a_pub[NOISE_PUBLIC_KEY_LEN];
	u8 b_priv[NOISE_PUBLIC_KEY_LEN], b_pub[NOISE_PUBLIC_KEY_LEN];
	u8 ck_i[NOISE_HASH_LEN], ck_r[NOISE_HASH_LEN];
	u8 k_i[NOISE_SYMMETRIC_KEY_LEN], k_r[NOISE_SYMMETRIC_KEY_LEN];

	NOISE_UT_ASSERT(ut_keypair(a_priv, a_pub));
	NOISE_UT_ASSERT(ut_keypair(b_priv, b_pub));

	/* NOISE: comment to address */
	memset(ck_i, 0x24, sizeof(ck_i));
	memcpy(ck_r, ck_i, sizeof(ck_r));

	NOISE_UT_ASSERT(mix_dh(ck_i, k_i, a_priv, b_pub));
	NOISE_UT_ASSERT(mix_dh(ck_r, k_r, b_priv, a_pub));

	NOISE_UT_ASSERT(memcmp(ck_i, ck_r, NOISE_HASH_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(k_i, k_r, NOISE_SYMMETRIC_KEY_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_message_ee_converges(void)
{
	u8 a_priv[NOISE_PUBLIC_KEY_LEN], a_pub[NOISE_PUBLIC_KEY_LEN];
	u8 b_priv[NOISE_PUBLIC_KEY_LEN], b_pub[NOISE_PUBLIC_KEY_LEN];
	u8 ck_i[NOISE_HASH_LEN], ck_r[NOISE_HASH_LEN];

	NOISE_UT_ASSERT(ut_keypair(a_priv, a_pub));
	NOISE_UT_ASSERT(ut_keypair(b_priv, b_pub));

	memset(ck_i, 0x37, sizeof(ck_i));
	memcpy(ck_r, ck_i, sizeof(ck_r));

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(message_ee(b_pub, a_priv, ck_i));
	NOISE_UT_ASSERT(message_ee(a_pub, b_priv, ck_r));

	NOISE_UT_ASSERT(memcmp(ck_i, ck_r, NOISE_HASH_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_message_se_converges(void)
{
	u8 a_priv[NOISE_PUBLIC_KEY_LEN], a_pub[NOISE_PUBLIC_KEY_LEN];
	u8 b_priv[NOISE_PUBLIC_KEY_LEN], b_pub[NOISE_PUBLIC_KEY_LEN];
	u8 ck1[NOISE_HASH_LEN], ck2[NOISE_HASH_LEN];

	NOISE_UT_ASSERT(ut_keypair(a_priv, a_pub));
	NOISE_UT_ASSERT(ut_keypair(b_priv, b_pub));

	memset(ck1, 0x5a, sizeof(ck1));
	memcpy(ck2, ck1, sizeof(ck2));

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(message_se(a_priv, b_pub, ck1));
	NOISE_UT_ASSERT(message_se(b_priv, a_pub, ck2));

	NOISE_UT_ASSERT(memcmp(ck1, ck2, NOISE_HASH_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_aead_roundtrip(void)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 pt[NOISE_PUBLIC_KEY_LEN];
	u8 pt_out[NOISE_PUBLIC_KEY_LEN];
	u8 ct[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 h_enc[NOISE_HASH_LEN], h_dec[NOISE_HASH_LEN];

	get_random_bytes(key, sizeof(key));
	get_random_bytes(pt, sizeof(pt));

	/* NOISE: comment to address */
	memset(h_enc, 0x11, sizeof(h_enc));
	memcpy(h_dec, h_enc, sizeof(h_dec));

	message_encrypt(ct, pt, sizeof(pt), key, h_enc);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(message_decrypt(pt_out, ct,
					noise_encrypted_len(sizeof(pt)),
					key, h_dec));
	NOISE_UT_ASSERT(memcmp(pt, pt_out, sizeof(pt)) == 0);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(h_enc, h_dec, NOISE_HASH_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_aead_tamper(void)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 pt[NOISE_PUBLIC_KEY_LEN];
	u8 pt_out[NOISE_PUBLIC_KEY_LEN];
	u8 ct[noise_encrypted_len(NOISE_PUBLIC_KEY_LEN)];
	u8 h_enc[NOISE_HASH_LEN], h_dec[NOISE_HASH_LEN];

	get_random_bytes(key, sizeof(key));
	get_random_bytes(pt, sizeof(pt));

	memset(h_enc, 0x22, sizeof(h_enc));
	memcpy(h_dec, h_enc, sizeof(h_dec));

	message_encrypt(ct, pt, sizeof(pt), key, h_enc);

	/* NOISE: comment to address */
	ct[0] ^= 0x01;

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(!message_decrypt(pt_out, ct,
					 noise_encrypted_len(sizeof(pt)),
					 key, h_dec));
	return true;
}

/* NOISE: comment to address */
static bool ut_derive_keys(void)
{
	u8 ck[NOISE_HASH_LEN];
	u8 k1a[NOISE_SYMMETRIC_KEY_LEN], k2a[NOISE_SYMMETRIC_KEY_LEN];
	u8 k1b[NOISE_SYMMETRIC_KEY_LEN], k2b[NOISE_SYMMETRIC_KEY_LEN];

	get_random_bytes(ck, sizeof(ck));

	derive_keys(k1a, k2a, ck);
	derive_keys(k1b, k2b, ck);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(k1a, k1b, NOISE_SYMMETRIC_KEY_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(k2a, k2b, NOISE_SYMMETRIC_KEY_LEN) == 0);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(k1a, k2a, NOISE_SYMMETRIC_KEY_LEN) != 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_mix_psk_converges(void)
{
	u8 psk[NOISE_SYMMETRIC_KEY_LEN];
	u8 ck1[NOISE_HASH_LEN], ck2[NOISE_HASH_LEN];
	u8 k1[NOISE_SYMMETRIC_KEY_LEN], k2[NOISE_SYMMETRIC_KEY_LEN];
	u8 h1[NOISE_HASH_LEN], h2[NOISE_HASH_LEN];

	get_random_bytes(psk, sizeof(psk));

	memset(ck1, 0x6b, sizeof(ck1));
	memcpy(ck2, ck1, sizeof(ck2));
	memset(h1, 0x1c, sizeof(h1));
	memcpy(h2, h1, sizeof(h2));

	mix_psk(psk, k1, ck1, h1);
	mix_psk(psk, k2, ck2, h2);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(ck1, ck2, NOISE_HASH_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(k1, k2, NOISE_SYMMETRIC_KEY_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(h1, h2, NOISE_HASH_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_message_e_deterministic(void)
{
	u8 eph[NOISE_PUBLIC_KEY_LEN];
	u8 dst1[NOISE_PUBLIC_KEY_LEN], dst2[NOISE_PUBLIC_KEY_LEN];
	u8 ck1[NOISE_HASH_LEN], ck2[NOISE_HASH_LEN];
	u8 h1[NOISE_HASH_LEN], h2[NOISE_HASH_LEN];

	get_random_bytes(eph, sizeof(eph));

	memset(ck1, 0x42, sizeof(ck1));
	memcpy(ck2, ck1, sizeof(ck2));
	memset(h1, 0x24, sizeof(h1));
	memcpy(h2, h1, sizeof(h2));

	message_e(dst1, eph, ck1, h1);
	message_e(dst2, eph, ck2, h2);

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(dst1, eph, NOISE_PUBLIC_KEY_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(dst1, dst2, NOISE_PUBLIC_KEY_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(ck1, ck2, NOISE_HASH_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(h1, h2, NOISE_HASH_LEN) == 0);
	return true;
}

/* NOISE: comment to address */
static bool ut_update_transcript_deterministic(void)
{
	u8 seed[NOISE_HASH_LEN];
	u8 h1[NOISE_HASH_LEN], h2[NOISE_HASH_LEN];
	u8 data[40];

	get_random_bytes(data, sizeof(data));

	memset(seed, 0x99, sizeof(seed));
	memcpy(h1, seed, sizeof(h1));
	memcpy(h2, seed, sizeof(h2));

	update_transcript(h1, data, sizeof(data));
	update_transcript(h2, data, sizeof(data));

	/* NOISE: comment to address */
	NOISE_UT_ASSERT(memcmp(h1, h2, NOISE_HASH_LEN) == 0);
	NOISE_UT_ASSERT(memcmp(h1, seed, NOISE_HASH_LEN) != 0);
	return true;
}

/* NOISE: comment to address */
bool noise_ikpsk2_selftest(void)
{
	bool ok = true;

	/* NOISE: comment to address */
	if (!ut_dh_symmetry())
		ok = false;
	if (!ut_mix_dh_converges())
		ok = false;
	if (!ut_message_ee_converges())
		ok = false;
	if (!ut_message_se_converges())
		ok = false;
	if (!ut_aead_roundtrip())
		ok = false;
	if (!ut_aead_tamper())
		ok = false;
	if (!ut_derive_keys())
		ok = false;
	if (!ut_mix_psk_converges())
		ok = false;
	if (!ut_message_e_deterministic())
		ok = false;
	if (!ut_update_transcript_deterministic())
		ok = false;

	if (ok)
		pr_info("noise_ut: all crypto selftests passed\n");
	else
		pr_err("noise_ut: crypto selftests FAILED\n");

	return ok;
}
