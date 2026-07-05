/* SPDX-License-Identifier: GPL-2.0 */
/* NOISE: comment to address */
#ifndef _NOISE_COOKIE_H
#define _NOISE_COOKIE_H

#include <net/noise.h>

/* NOISE: comment to address */
void noise_mac1_stamp(struct ikpsk2_msg1 *m1,
		      const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN]);

/* NOISE: comment to address */
bool __must_check noise_mac1_verify(const struct ikpsk2_msg1 *m1,
				    const u8 responder_pubkey[NOISE_PUBLIC_KEY_LEN]);

#endif /* _NOISE_COOKIE_H */
