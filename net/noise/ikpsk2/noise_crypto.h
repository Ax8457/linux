/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Private/internal crypto helpers shared between the Noise IKpsk2
 *	source files. The public API (structs, handshake and transport
 *	entry points) lives in <net/noise.h>.
 *
 *	Axel Biegalski - HWU MSc project
 */
#ifndef NOISE_CRYPTO_H
#define NOISE_CRYPTO_H

#include <net/noise.h>

/* internal symmetric-state / DH helpers (net/noise/ikpsk2/noise_crypto.c) */
void update_transcript(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len);
void init_handshake(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], const u8 remote_pubkey[NOISE_PUBLIC_KEY_LEN]);
void message_e(u8 dst[NOISE_PUBLIC_KEY_LEN], const u8 ephemeral_pubkey_initiator[NOISE_PUBLIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN]);
bool __must_check mix_dh(u8 chaining_key[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 private_key[NOISE_PUBLIC_KEY_LEN], const u8 public_key[NOISE_PUBLIC_KEY_LEN]);
void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN]);
bool __must_check message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN]);
void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN]);
bool __must_check message_ee(const u8 ephemeral_public[NOISE_PUBLIC_KEY_LEN], const u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN]);
bool __must_check message_se(const u8 ephemeral_private_key[NOISE_PUBLIC_KEY_LEN], const u8 remote_static[NOISE_PUBLIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN]);
void mix_psk(u8 psk[NOISE_SYMMETRIC_KEY_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN]);
void derive_keys(u8 first_key[NOISE_SYMMETRIC_KEY_LEN], u8 second_key[NOISE_SYMMETRIC_KEY_LEN], const u8 chaining_key[NOISE_HASH_LEN]);
void generate_ephemeral_secret(u8 private_key[NOISE_PUBLIC_KEY_LEN]);
void generate_public(u8 public_key[NOISE_PUBLIC_KEY_LEN], const u8 private_key[NOISE_PUBLIC_KEY_LEN]);

#endif /* NOISE_CRYPTO_H */
