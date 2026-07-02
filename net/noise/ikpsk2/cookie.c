// SPDX-License-Identifier: GPL-2.0
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	mac1: a cheap keyed-BLAKE2s tag on the handshake initiation (msg1) so the
 *	responder can drop forged/garbage messages with a single hash before
 *	spending Curve25519. Inspired by WireGuard's cookie.c, reduced to mac1
 *	only:
 *
 *	  - mac2 and the whole cookie/return-routability machinery are omitted:
 *	    this transport runs over TCP, whose 3-way handshake already proves the
 *	    peer's source address (the problem mac2 exists to solve on UDP).
 *
 *	The mac1 key is derived from the *responder's* static public key, which is
 *	a public value, so mac1 is a DoS / anti-scanning filter, not peer
 *	authentication (that is the PSK + static-key DH inside the handshake). Like
 *	the framing header, mac1 is outer framing and is not mixed into the Noise
 *	transcript.
 *
 *	Axel Biegalski - HWU MSc project
 */
#include <linux/string.h>
#include <linux/stddef.h>		/* offsetof */
#include <crypto/blake2s.h>
#include <crypto/utils.h>		/* crypto_memneq */

#include <net/noise.h>
#include "cookie.h"

/* label mixed into the mac1 key derivation (8 bytes, no NUL terminator) */
static const u8 mac1_key_label[NOISE_MAC1_LABEL_LEN] __nonstring = "mac1----";

/* mac1 key = BLAKE2s("mac1----" || responder_static_public) */
static void noise_mac1_key(u8 key[NOISE_SYMMETRIC_KEY_LEN],
			   const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	struct blake2s_ctx blake;

	blake2s_init(&blake, NOISE_SYMMETRIC_KEY_LEN);
	blake2s_update(&blake, mac1_key_label, NOISE_MAC1_LABEL_LEN);
	blake2s_update(&blake, responder_pubkey, NOISE_PUBLIC_KEY_LEN);
	blake2s_final(&blake, key);
}

/* mac = keyed-BLAKE2s over msg1 from the start up to (excluding) the mac1 field.
 * blake2s() one-shot here is key-first: blake2s(key, keylen, in, inlen, out, outlen).
 */
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

void noise_mac1_stamp(struct ikpsk2_msg1 *m1,
		      const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	noise_mac1_compute(m1->mac1, m1, responder_pubkey);
}
EXPORT_SYMBOL(noise_mac1_stamp);

bool noise_mac1_verify(const struct ikpsk2_msg1 *m1,
		       const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	u8 expected[NOISE_MAC1_LEN];
	bool ok;

	noise_mac1_compute(expected, m1, responder_pubkey);
	/* constant-time compare (crypto_memneq returns 0 on equal) */
	ok = crypto_memneq(expected, m1->mac1, NOISE_MAC1_LEN) == 0;
	memzero_explicit(expected, sizeof(expected));
	return ok;
}
EXPORT_SYMBOL(noise_mac1_verify);
