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
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/printk.h>
#include <linux/unaligned.h>
#include <linux/timekeeping.h>
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

/*
	Rekey policy: true once the current keypair has sent REKEY_AFTER_MESSAGES
	records or has lived for REKEY_AFTER_TIME seconds. The caller drops the
	connection so the transport reconnects and a fresh handshake re-keys both
	directions. Driven by the sending side (its own sending_counter / birthdate),
	so whichever peer is busier triggers the rekey first.
*/
bool noise_peer_should_rekey(struct noise_peer *peer)
{
	u64 sent = atomic64_read(&peer->symmetric_keys.sending_counter);

	if (sent >= REKEY_AFTER_MESSAGES)
		return true;

	return (u64)ktime_get_seconds() - peer->symmetric_keys.birthdate >=
	       REKEY_AFTER_TIME;
}
EXPORT_SYMBOL(noise_peer_should_rekey);

/*
	Seal one plaintext record into the wire framing:
	[__be32 body_len][__le64 counter][ciphertext]
	Returns the total number of wire bytes written to @dst, or <0 on error.
*/
int noise_record_seal(struct noise_peer *peer, u8 *dst, const u8 *pt, u32 ptlen)
{
	u32 ctlen = ptlen + NOISE_AUTHTAG_LEN;
	u32 body_len = NOISE_REC_CTR_SIZE + ctlen;
	u64 counter;

	if (!noise_transport_encrypt(peer,
				     dst + NOISE_REC_LEN_SIZE + NOISE_REC_CTR_SIZE,
				     pt, ptlen, &counter)) {
		pr_warn_ratelimited("noise: seal failed (counter exhausted)\n");
		return -EINVAL;
	}

	pr_info_once("noise: transport encryption active (sealing records)\n");
	put_unaligned_be32(body_len, dst);
	put_unaligned_le64(counter, dst + NOISE_REC_LEN_SIZE);
	return NOISE_REC_LEN_SIZE + body_len;
}
EXPORT_SYMBOL(noise_record_seal);

/*
	Open a frame body [__le64 counter][ciphertext] of @body_len bytes into @pt.
	Enforces a monotonic (in-order TCP) anti-replay check on the counter.
	Returns the recovered plaintext length, or <0 on error.
*/
int noise_record_open(struct noise_peer *peer, const u8 *body, u32 body_len, u8 *pt)
{
	u32 ctlen;
	u64 counter;

	if (body_len < NOISE_REC_CTR_SIZE + NOISE_AUTHTAG_LEN) {
		pr_warn_ratelimited("noise: drop short record (body_len=%u)\n",
				    body_len);
		return -EBADMSG;
	}

	counter = get_unaligned_le64(body);
	ctlen = body_len - NOISE_REC_CTR_SIZE;

	/* in-order stream: a counter that goes backwards is a replay */
	if (counter < peer->symmetric_keys.receiving_counter) {
		pr_warn_ratelimited("noise: drop replay/out-of-order record (counter=%llu, expected>=%llu)\n",
				    counter, peer->symmetric_keys.receiving_counter);
		return -EBADMSG;
	}

	if (!noise_transport_decrypt(peer, pt, body + NOISE_REC_CTR_SIZE, ctlen,
				     counter)) {
		pr_warn_ratelimited("noise: AEAD auth failed (counter=%llu) - key/framing mismatch or tampering\n",
				    counter);
		return -EBADMSG;
	}

	pr_info_once("noise: transport decryption active (opening records)\n");
	peer->symmetric_keys.receiving_counter = counter + 1;
	return ctlen - NOISE_AUTHTAG_LEN;
}
EXPORT_SYMBOL(noise_record_open);

void noise_rx_reset(struct noise_rx *rx)
{
	kfree(rx->body);
	kfree(rx->pt);
	memset(rx, 0, sizeof(*rx));
}
EXPORT_SYMBOL(noise_rx_reset);
