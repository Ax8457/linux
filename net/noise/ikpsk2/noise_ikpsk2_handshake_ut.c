// SPDX-License-Identifier: GPL-2.0
/* NOISE: comment to address */

#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/printk.h>
#include <linux/slab.h>

#include <crypto/curve25519.h>

#include <net/noise.h>
#include "noise_ikpsk2_ut.h"

/* NOISE: comment to address */
#define HS_CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			pr_err("noise_hs_ut: FAILED: %s (%s:%d)\n",	\
			       #cond, __func__, __LINE__);		\
			goto out;					\
		}							\
	} while (0)

/* NOISE: comment to address */
static bool ut_make_identity(struct noise_identity *id)
{
	curve25519_generate_secret(id->static_private);
	return curve25519_generate_public(id->static_public, id->static_private);
}

/* NOISE: comment to address */
bool noise_ikpsk2_handshake_selftest(void)
{
	struct noise_identity init_id = {};
	struct noise_identity resp_id = {};
	struct noise_peer *ini = NULL;
	struct noise_peer *res = NULL;
	struct ikpsk2_msg1 m1 = {};
	struct ikpsk2_msg2 m2 = {};
	u8 psk[NOISE_SYMMETRIC_KEY_LEN];
	bool ok = false;

	ini = kzalloc(sizeof(*ini), GFP_KERNEL);
	res = kzalloc(sizeof(*res), GFP_KERNEL);
	HS_CHECK(ini && res);

	/* NOISE: comment to address */
	HS_CHECK(ut_make_identity(&init_id));
	HS_CHECK(ut_make_identity(&resp_id));
	get_random_bytes(psk, sizeof(psk));

	/* NOISE: comment to address */
	ini->handshake.static_identity = &init_id;
	res->handshake.static_identity = &resp_id;
	memcpy(ini->handshake.remote_static, resp_id.static_public,
	       NOISE_PUBLIC_KEY_LEN);
	memcpy(ini->handshake.psk, psk, NOISE_SYMMETRIC_KEY_LEN);
	memcpy(res->handshake.psk, psk, NOISE_SYMMETRIC_KEY_LEN);

	/* NOISE: comment to address */
	HS_CHECK(noise_handshake_create_initiation(&m1, &ini->handshake));
	HS_CHECK(handshake_consume_initiation(&m1, res));

	/* NOISE: comment to address */
	HS_CHECK(memcmp(ini->handshake.chaining_key,
			res->handshake.chaining_key, NOISE_HASH_LEN) == 0);
	HS_CHECK(memcmp(ini->handshake.hash_transcript,
			res->handshake.hash_transcript, NOISE_HASH_LEN) == 0);

	/* NOISE: comment to address */
	HS_CHECK(memcmp(res->handshake.remote_static,
			init_id.static_public, NOISE_PUBLIC_KEY_LEN) == 0);
	HS_CHECK(memcmp(res->handshake.remote_ephemeral,
			m1.unencrypted_ephemeral, NOISE_PUBLIC_KEY_LEN) == 0);

	/* NOISE: comment to address */
	HS_CHECK(handshake_create_response(&m2, res));
	HS_CHECK(handshake_consume_response(&m2, ini));

	/* NOISE: comment to address */
	HS_CHECK(memcmp(ini->handshake.chaining_key,
			res->handshake.chaining_key, NOISE_HASH_LEN) == 0);
	HS_CHECK(memcmp(ini->handshake.hash_transcript,
			res->handshake.hash_transcript, NOISE_HASH_LEN) == 0);

	/* NOISE: comment to address */
	HS_CHECK(begin_session(ini));
	HS_CHECK(begin_session(res));

	/* NOISE: comment to address */
	HS_CHECK(ini->symmetric_keys.i_am_the_initiator);
	HS_CHECK(!res->symmetric_keys.i_am_the_initiator);

	/* NOISE: comment to address */
	HS_CHECK(memcmp(ini->symmetric_keys.sending_key,
			res->symmetric_keys.receiving_key,
			NOISE_SYMMETRIC_KEY_LEN) == 0);
	HS_CHECK(memcmp(ini->symmetric_keys.receiving_key,
			res->symmetric_keys.sending_key,
			NOISE_SYMMETRIC_KEY_LEN) == 0);

	pr_info("noise_hs_ut: handshake selftest passed\n");
	ok = true;

out:
	kfree_sensitive(ini);
	kfree_sensitive(res);
	memzero_explicit(psk, sizeof(psk));
	memzero_explicit(&init_id, sizeof(init_id));
	memzero_explicit(&resp_id, sizeof(resp_id));
	return ok;
}
