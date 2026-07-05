// SPDX-License-Identifier: GPL-2.0
/* NOISE: comment to address */
#include <linux/string.h>
#include <linux/stddef.h>
#include <crypto/blake2s.h>
#include <crypto/utils.h>

#include <net/noise.h>
#include "cookie.h"

/* NOISE: comment to address */
static const u8 mac1_key_label[NOISE_MAC1_LABEL_LEN] __nonstring = "mac1----";

/* NOISE: comment to address */
static void noise_mac1_key(u8 key[NOISE_SYMMETRIC_KEY_LEN],
			   const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct blake2s_ctx blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&blake, mac1_key_label, NOISE_MAC1_LABEL_LEN);
	blake2s_update(&blake, responder_pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, key);
}

/* NOISE: comment to address */
static void noise_mac1_compute(u8 mac[NOISE_MAC1_LEN],
			       const struct ikpsk2_msg1 *m1,
			       const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];

	noise_mac1_key(key, responder_pubkey);
	blake2s(key, NOISE_SYMMETRIC_KEY_LEN,
		(const u8 *)m1, offsetof(struct ikpsk2_msg1, mac1),
		mac, NOISE_MAC1_LEN);
	memzero_explicit(key, sizeof(key));
}

/* NOISE: comment to address */
void noise_mac1_stamp(struct ikpsk2_msg1 *m1,
		      const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	noise_mac1_compute(m1->mac1, m1, responder_pubkey);
}
EXPORT_SYMBOL(noise_mac1_stamp);

/* NOISE: comment to address */
bool noise_mac1_verify(const struct ikpsk2_msg1 *m1,
		       const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	u8 expected[NOISE_MAC1_LEN];
	bool ok;

	noise_mac1_compute(expected, m1, responder_pubkey);
	ok = crypto_memneq(expected, m1->mac1, NOISE_MAC1_LEN) == 0;
	memzero_explicit(expected, sizeof(expected));
	return ok;
}
EXPORT_SYMBOL(noise_mac1_verify);
