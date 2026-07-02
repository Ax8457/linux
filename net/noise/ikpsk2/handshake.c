// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/
#include <linux/timekeeping.h>
#include <asm/byteorder.h>

#include "noise_crypto.h"

/*
 * Message framing helpers (WireGuard-inspired).
 *
 * noise_message_header_set() stamps the fixed magic/version onto an outgoing
 * message; noise_message_classify() validates an incoming header and returns
 * its type so the receiver can switch() on it. The header is framing only and
 * is not part of the Noise transcript.
 */
void noise_message_header_set(struct noise_message_header *hdr, u8 type)
{
	hdr->magic = cpu_to_be32(NOISE_MSG_MAGIC);
	hdr->type = type;
	hdr->version = NOISE_MSG_VERSION;
	hdr->reserved[0] = 0;
	hdr->reserved[1] = 0;
}

enum noise_message_type noise_message_classify(const struct noise_message_header *hdr)
{
	if (be32_to_cpu(hdr->magic) != NOISE_MSG_MAGIC)
		return NOISE_MSG_INVALID;
	if (hdr->version != NOISE_MSG_VERSION)
		return NOISE_MSG_INVALID;
	if (hdr->reserved[0] | hdr->reserved[1])
		return NOISE_MSG_INVALID;

	switch (hdr->type) {
	case NOISE_MSG_HANDSHAKE_INITIATION:
	case NOISE_MSG_HANDSHAKE_RESPONSE:
	case NOISE_MSG_HANDSHAKE_ERROR:
		return hdr->type;
	default:
		return NOISE_MSG_INVALID;
	}
}



//INITIATOR -> handshake initiation creation 
bool noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake)
{	
	//vars 
	u8 timestamp[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;
	//init handshake between client and server
	/*
	*	H1 = hash(H0 || Static_pubkey_responder)
	*/

	init_handshake(handshake->chaining_key, handshake->hash_transcript, handshake->remote_static);

	/* stamp the framing header so the responder can route this as an initiation */
	noise_message_header_set(&m1->header, NOISE_MSG_HANDSHAKE_INITIATION);

	/*
		e : C1 & H2
		C1 = hkdf1(C0,E_pub_i)
		H2 = hash(H1, E_pub_i)

	*/
	//generate ephemerals
	curve25519_generate_secret(handshake->ephemeral_private);
	if (!curve25519_generate_public(m1->unencrypted_ephemeral, handshake->ephemeral_private)){
		goto out;
	}

	//hkdf & hash update
	message_e(m1->unencrypted_ephemeral,m1->unencrypted_ephemeral, handshake->chaining_key, handshake->hash_transcript);

	/*
		es: C2 & k1
		C2 || k1 = hkdf2(C1, dh(E_priv_i,S_pub_r))
	*/
	if (!mix_dh(handshake->chaining_key, key , handshake->ephemeral_private, handshake->remote_static)){
		goto out;
	}
	
	/*
		s: timestamps encrypt & H3
		S pub encrypted = aenc(k1,0,S_pub_i,H2)
		H3 = hash(H2, S_pub_encrypted)
	*/
	message_encrypt(m1->encrypted_static, handshake->static_identity->static_public, NOISE_PUBLIC_KEY_LEN ,key, handshake->hash_transcript);

	/*
		ss: C3 & K2
		C3 || k2 = hkdf2(C2, dh(S_priv_i, S_pub_r))
		/!\ in the future use pre computed static static instead
	*/
	if (!mix_dh(handshake->chaining_key, key, handshake->static_identity->static_private, handshake->remote_static))
	{ 
		goto out; 
	}

	/*
		encrypte ts & H4
	*/
	tai64n_now(timestamp);
	message_encrypt(m1->encrypted_timestamp, timestamp, NOISE_TIMESTAMP_LEN, key, handshake->hash_transcript);

	//update state and bool
	handshake->state = HANDSHAKE_CREATED_INITIATION;
	ret = true;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}



bool handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer)
{
	//for the moment single client model
	struct noise_handshake *handshake = &peer->handshake;
	bool ret = false;
	u8 chaining_key[NOISE_HASH_LEN];
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 s[NOISE_PUBLIC_KEY_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 t[NOISE_TIMESTAMP_LEN];
	u8 key[NOISE_SYMMETRIC_KEY_LEN];

	/*
		H1
	*/
	init_handshake(chaining_key, hash_transcript, peer->handshake.static_identity->static_public);

	/*
		e : C1 & H2
	*/
	message_e(e,m1->unencrypted_ephemeral, chaining_key, hash_transcript );

	/*
		es: C2 & K1
	*/
	if (!mix_dh(chaining_key, key, peer->handshake.static_identity->static_private,e))
	{
		goto out;
	}

	/*
		dec S_pub_i & H3
	*/
	if (!message_decrypt(s, m1->encrypted_static, NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN, key, hash_transcript))
	{
		goto out;
	}

	// part missing => look up in hash table in multiple client, for the moment -> single client
	/*
		ss : C3 + K2
	*/
	if (!mix_dh(chaining_key,key,peer->handshake.static_identity->static_private, s)){
		goto out;
	}

	/*
		t: dec timestamp + h4
	*/
	if (!message_decrypt(t, m1->encrypted_timestamp, NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN,key,hash_transcript)){
		goto out;
	}

	/* Replay defense is NOT done here: this per-connection handshake struct is
	 * freshly zeroed for every connection, so it cannot remember a client's
	 * previous timestamp. The recovered timestamp is stored below and checked
	 * by the caller against a persistent, per-pubkey record (noise_client_check_ts)
	 * once the client has been authenticated (PSK found). See svc_noise_handshake().
	 */

	/*
		Update peer
	*/
	memcpy(handshake->remote_ephemeral, e, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->remote_static, s, NOISE_PUBLIC_KEY_LEN);
    memcpy(handshake->latest_timestamp, t, NOISE_TIMESTAMP_LEN);
    memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);
    memcpy(handshake->hash_transcript, hash_transcript, NOISE_HASH_LEN);

	handshake->state = HANDSHAKE_CONSUMED_INITIATION;
	ret = true;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash_transcript, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	return ret;
}	

bool handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	bool ret = false;

	/* stamp the framing header so the initiator can route this as a response */
	noise_message_header_set(&m2->header, NOISE_MSG_HANDSHAKE_RESPONSE);

	/*
		e: generate ephemerals + C4 & H5
	*/
	curve25519_generate_secret(peer->handshake.ephemeral_private);
	if (!curve25519_generate_public(m2->ephemeral_public_key, peer->handshake.ephemeral_private)){
		goto out;
	}

	message_e(m2->ephemeral_public_key, m2->ephemeral_public_key, peer->handshake.chaining_key, peer->handshake.hash_transcript);

	/*
		ee : C5
	*/

	if (!message_ee(peer->handshake.remote_ephemeral, peer->handshake.ephemeral_private,peer->handshake.chaining_key))
	{
		goto out;
	}

	/*
		se : C6
	*/
	if (!message_se(peer->handshake.ephemeral_private, peer->handshake.remote_static,peer->handshake.chaining_key))
	{
		goto out;
	}

	/*
		psk
	*/
	mix_psk(peer->handshake.psk, key, peer->handshake.chaining_key, peer->handshake.hash_transcript);

	message_encrypt(m2->encrypted_empty, (u8 *)"", 0, key, peer->handshake.hash_transcript);

	//update state
	peer->handshake.state = HANDSHAKE_CREATED_RESPONSE;
	ret = true;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;

}

bool handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer)
{
	struct noise_handshake *handshake = &peer->handshake; //for the moment no index table
	bool ret = false;
	u8 key[NOISE_SYMMETRIC_KEY_LEN];
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	u8 e[NOISE_PUBLIC_KEY_LEN];
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	u8 preshared_key[NOISE_SYMMETRIC_KEY_LEN];
	u8 empty[0];

	/*
		Complete handshake temp
	*/
	memcpy(hash_transcript, handshake->hash_transcript, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake->chaining_key, NOISE_HASH_LEN);
	memcpy(ephemeral_private, handshake->ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	memcpy(preshared_key, handshake->psk, NOISE_SYMMETRIC_KEY_LEN);

	/*
		e : C4 + H5
	*/
	message_e(e,m2->ephemeral_public_key, chaining_key, hash_transcript);
	/*
		ee : C5
	*/
	if (!message_ee(e, ephemeral_private, chaining_key)){
		goto out;
	}

	/*
		se: C6
	*/
	if(!message_se(handshake->static_identity->static_private, e, chaining_key))
	{
		goto out;
	}

	/*
		psk : C7, pi k3 & H6 + H7
	*/
	mix_psk(preshared_key,key,chaining_key,hash_transcript);

	/*
		decrypt empty + H7
	*/
	if (!message_decrypt(empty,m2->encrypted_empty,NOISE_AUTHTAG_LEN,key,hash_transcript)){
		goto out;
	}

	/*
		copy everything to peer
	*/
	memcpy(handshake->hash_transcript, hash_transcript, NOISE_HASH_LEN);
	memcpy(handshake->chaining_key, chaining_key, NOISE_HASH_LEN);

	//update state
	handshake->state = HANDSHAKE_CONSUMED_RESPONSE;
	ret = true;

out:
	memzero_explicit(key, NOISE_SYMMETRIC_KEY_LEN);
	memzero_explicit(hash_transcript, NOISE_HASH_LEN);
	memzero_explicit(chaining_key, NOISE_HASH_LEN);
	memzero_explicit(ephemeral_private, NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(e, NOISE_PUBLIC_KEY_LEN);
	memzero_explicit(preshared_key, NOISE_SYMMETRIC_KEY_LEN);
	return ret;
}

/*
	Derive keys and begin session
*/
bool begin_session(struct noise_peer *peer)
{
	bool ret = false;
	if (peer->handshake.state != HANDSHAKE_CREATED_RESPONSE && peer->handshake.state != HANDSHAKE_CONSUMED_RESPONSE)
	{
		goto out;
	}
	peer->symmetric_keys.i_am_the_initiator = peer->handshake.state == HANDSHAKE_CONSUMED_RESPONSE;
	if(peer->symmetric_keys.i_am_the_initiator){
		derive_keys(peer->symmetric_keys.sending_key, peer->symmetric_keys.receiving_key, peer->handshake.chaining_key);
	}
	else {
		derive_keys(peer->symmetric_keys.receiving_key, peer->symmetric_keys.sending_key, peer->handshake.chaining_key);
	}

	/* Fresh keypair: restart the nonce counters and stamp its birthdate. The
	 * peer struct is reused across reconnects, so this reset is required both
	 * for the new session's counters to start clean and for the rekey
	 * thresholds to measure the current keypair only.
	 */
	atomic64_set(&peer->symmetric_keys.sending_counter, 0);
	peer->symmetric_keys.receiving_counter = 0;
	peer->symmetric_keys.birthdate = ktime_get_seconds();

	ret = true;
out:
	return ret;
}

EXPORT_SYMBOL(noise_message_header_set);
EXPORT_SYMBOL(noise_message_classify);
EXPORT_SYMBOL(noise_handshake_create_initiation);
EXPORT_SYMBOL(handshake_consume_initiation);
EXPORT_SYMBOL(handshake_create_response);
EXPORT_SYMBOL(handshake_consume_response);
EXPORT_SYMBOL(begin_session);