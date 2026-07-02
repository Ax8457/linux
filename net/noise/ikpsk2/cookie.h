/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	mac1 handshake DoS gate (see cookie.c). Module-internal API used by the
 *	handshake code; not part of the public <net/noise.h> interface.
 *
 *	Axel Biegalski - HWU MSc project
 */
#ifndef _NOISE_COOKIE_H
#define _NOISE_COOKIE_H

#include <net/noise.h>

/* Compute and write m1->mac1, keyed by the responder (server) static public
 * key. Called by the initiator after building the rest of msg1.
 */
void noise_mac1_stamp(struct ikpsk2_msg1 *m1,
		      const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN]);

/* Recompute mac1 and constant-time compare against m1->mac1. Returns true iff
 * valid. Called by the responder before any Curve25519, keyed by its own
 * static public key.
 */
bool __must_check noise_mac1_verify(const struct ikpsk2_msg1 *m1,
				    const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN]);

#endif /* _NOISE_COOKIE_H */
