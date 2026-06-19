// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework
*
*	Transport phase: encrypt/decrypt with session keys derived after handshake
*
*	Axel Biegalski
*/
#include <linux/types.h>
#include <linux/atomic.h>
#include <crypto/chacha20poly1305.h>

#include "noise_crypto.h"

/*
	encrypt function
*/
bool __must_check noise_transport_encrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 *counter)
{
	struct noise_keypair *keypair = &peer->symmetric_keys;
	u64 nonce;

	nonce = atomic64_inc_return(&keypair->sending_counter) - 1;
	if (nonce >= REJECT_AFTER_MESSAGES)
		return false;

	chacha20poly1305_encrypt(dst, src, src_len, NULL, 0, nonce, keypair->sending_key);

	if (counter)
		*counter = nonce;

	return true;
}

/*
	Decrypt function
*/
bool __must_check noise_transport_decrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 counter)
{
	struct noise_keypair *keypair = &peer->symmetric_keys;

	if (src_len < NOISE_AUTHTAG_LEN)
		return false;

	if (counter >= REJECT_AFTER_MESSAGES)
		return false;

	return chacha20poly1305_decrypt(dst, src, src_len, NULL, 0, counter, keypair->receiving_key);
}

EXPORT_SYMBOL(noise_transport_encrypt);
EXPORT_SYMBOL(noise_transport_decrypt);
