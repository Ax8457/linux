// HWU MSc project
/*
*	NFSv4 Data-In-Flight Encryption over Noise protocol Framework 
*
*	Axel Biegalski
*/

/*
	Libs
*/
#include <linux/types.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>
#include <linux/rwsem.h>
#include <linux/mutex.h>
#include <linux/kref.h>

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

#include <linux/kernel.h>
#include <linux/param.h>
#include <linux/skbuff.h>
#include <linux/version.h>

#include "noise_crypto.h"

/* NOISE BLAKE2s library compat: v6.19 renamed struct blake2s_state ->
 * blake2s_ctx and reordered the one-shot blake2s() arguments. Map the old
 * struct name to the new one so the same source builds on both <6.19 (e.g.
 * out-of-tree on 6.1) and >=6.19 / 7.x kernels.
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
#define blake2s_state blake2s_ctx
#endif
 
/*
	Vars
*/
//noise info
static const u8 handshake_name[37] __nonstring = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
static const u8 identifier_name[14] __nonstring = "Axel Biegalski";
//Chaining key and Hash transcript
u8 handshake_init_hash[NOISE_HASH_LEN] __ro_after_init;
u8 handshake_init_chaining_key[NOISE_HASH_LEN] __ro_after_init;

/*
	Init function
*/
void __init ikpsk2_noise_init(void)
{
	/*
		handshake_init_chaining_key = C0
		handshake_init_hash = H0
	*/
	struct blake2s_state blake;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 19, 0)
	/* new arg order: (key, keylen, in, inlen, out, outlen) */
	blake2s(NULL, 0, handshake_name, sizeof(handshake_name),
		handshake_init_chaining_key, NOISE_HASH_LEN);
#else
	/* old arg order: (out, in, key, outlen, inlen, keylen) */
	blake2s(handshake_init_chaining_key, handshake_name, NULL,
		NOISE_HASH_LEN, sizeof(handshake_name), 0);
#endif
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, handshake_init_chaining_key, NOISE_HASH_LEN);
	blake2s_update(&blake, identifier_name, sizeof(identifier_name));
	blake2s_final(&blake, handshake_init_hash);
}

/*
	Update Hash Transcript
*/
//update hash transcript
void update_transcript(u8 hash[NOISE_HASH_LEN], const u8 *src, size_t src_len)
{
	struct blake2s_state blake;
	blake2s_init(&blake, NOISE_HASH_LEN);
	blake2s_update(&blake, hash, NOISE_HASH_LEN);
	blake2s_update(&blake, src, src_len);
	blake2s_final(&blake, hash);
}

/*
	Handshake Init function
	H1 = Hash(H0, Remote Serve Pubkey (Static))
*/
void init_handshake(u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN], const u8 remote_pubkey[NOISE_PUBLIC_KEY_LEN])
{
	memcpy(hash, handshake_init_hash, NOISE_HASH_LEN);
	memcpy(chaining_key, handshake_init_chaining_key, NOISE_HASH_LEN); //update hanshake struct in client peer struct
	update_transcript(hash, remote_pubkey, NOISE_PUBLIC_KEY_LEN);
}

/*
 * This function was taken from wireguard source code
 *   https://github.com/WireGuard/wireguard-linux/blob/stable/drivers/net/wireguard/noise.c
*/
static void hmac(u8 *out, const u8 *in, const u8 *key, const size_t inlen, const size_t keylen)
{
	struct blake2s_state blake;
	u8 x_key[BLAKE2S_BLOCK_SIZE] __aligned(__alignof__(u32)) = { 0 };
	u8 i_hash[BLAKE2S_HASH_SIZE] __aligned(__alignof__(u32));
	int i;

	if (keylen > BLAKE2S_BLOCK_SIZE) {
		blake2s_init(&blake, BLAKE2S_HASH_SIZE);
		blake2s_update(&blake, key, keylen);
		blake2s_final(&blake, x_key);
	} else
		memcpy(x_key, key, keylen);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x36;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, in, inlen);
	blake2s_final(&blake, i_hash);

	for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
		x_key[i] ^= 0x5c ^ 0x36;

	blake2s_init(&blake, BLAKE2S_HASH_SIZE);
	blake2s_update(&blake, x_key, BLAKE2S_BLOCK_SIZE);
	blake2s_update(&blake, i_hash, BLAKE2S_HASH_SIZE);
	blake2s_final(&blake, i_hash);

	memcpy(out, i_hash, BLAKE2S_HASH_SIZE);
	memzero_explicit(x_key, BLAKE2S_BLOCK_SIZE);
	memzero_explicit(i_hash, BLAKE2S_HASH_SIZE);
}

/*  https://github.com/WireGuard/wireguard-linux/blob/stable/drivers/net/wireguard/noise.c
 *  This function was taken from wireguard source code which states:
 *  " This is Hugo Krawczyk's HKDF:
 *  - https://eprint.iacr.org/2010/264.pdf
 *  - https://tools.ietf.org/html/rfc5869 " 
 */
static void kdf(u8 *first_dst, u8 *second_dst, u8 *third_dst, const u8 *data, size_t first_len, size_t second_len, size_t third_len, size_t data_len, const u8 chaining_key[NOISE_HASH_LEN])
{
	u8 output[BLAKE2S_HASH_SIZE + 1];
	u8 secret[BLAKE2S_HASH_SIZE];

	WARN_ON(IS_ENABLED(DEBUG) &&
		(first_len > BLAKE2S_HASH_SIZE ||
		 second_len > BLAKE2S_HASH_SIZE ||
		 third_len > BLAKE2S_HASH_SIZE ||
		 ((second_len || second_dst || third_len || third_dst) &&
		  (!first_len || !first_dst)) ||
		 ((third_len || third_dst) && (!second_len || !second_dst))));

	/* Extract entropy from data into secret */
	hmac(secret, data, chaining_key, data_len, NOISE_HASH_LEN);

	if (!first_dst || !first_len)
		goto out;

	/* Expand first key: key = secret, data = 0x1 */
	output[0] = 1;
	hmac(output, output, secret, 1, BLAKE2S_HASH_SIZE);
	memcpy(first_dst, output, first_len);

	if (!second_dst || !second_len)
		goto out;

	/* Expand second key: key = secret, data = first-key || 0x2 */
	output[BLAKE2S_HASH_SIZE] = 2;
	hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(second_dst, output, second_len);

	if (!third_dst || !third_len)
		goto out;

	/* Expand third key: key = secret, data = second-key || 0x3 */
	output[BLAKE2S_HASH_SIZE] = 3;
	hmac(output, output, secret, BLAKE2S_HASH_SIZE + 1, BLAKE2S_HASH_SIZE);
	memcpy(third_dst, output, third_len);

out:
	/* Clear sensitive data from stack */
	memzero_explicit(secret, BLAKE2S_HASH_SIZE);
	memzero_explicit(output, BLAKE2S_HASH_SIZE + 1);
}

/*
	Message1 : e, es ,s ,ss 
	e:
		C1 = hkdf(C0, Ephemeral pub initiator)
		H2 = hash(H1, Ephermeral pub initiator)
		
	/!\ HKDF : only one expansion
*/
//e
void message_e(u8 dst[NOISE_PUBLIC_KEY_LEN], const u8 ephemeral_pubkey_initiator[NOISE_PUBLIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN]) {
    
    if (ephemeral_pubkey_initiator != dst) {
        memcpy(dst, ephemeral_pubkey_initiator, NOISE_PUBLIC_KEY_LEN);
    }
    kdf(   
        chaining_key,       
        NULL, NULL,              // one expansion (hkdf1)
        ephemeral_pubkey_initiator,                              
        NOISE_HASH_LEN,
        0 , 0, //len of second and thirdhkey       
        NOISE_PUBLIC_KEY_LEN, 
        chaining_key          
    );

    // H2 = hash(H1, Ephemeral pub initiator)
    update_transcript(hash, dst, NOISE_PUBLIC_KEY_LEN); 
}

/*
	Diffie Hellman shared secret mixing function
	C2 || K1 = hkdf(C1, dh(Ephemeral public initiator, Ephemeral private initiator)) 
*/
//es
bool __must_check mix_dh(u8 chaining_key[NOISE_HASH_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], const u8 private_key[NOISE_PUBLIC_KEY_LEN], const u8 public_key[NOISE_PUBLIC_KEY_LEN])
{
	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];
	//diffie hellman share secret
    if (!curve25519(dh_calculation, private_key, public_key)){
		return false;
	}
	kdf(
        chaining_key, //C2
        key, //k1
        NULL, 
        dh_calculation, 
        NOISE_HASH_LEN,
        NOISE_SYMMETRIC_KEY_LEN, 
        0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);
	return true;
	//extract
}

/* 
	Encryption/Decryption function
	public initiator enc + H3
	H3 = hash(H2, Spubinitenc)
*/
//s
//client side
void message_encrypt(u8 *dst_ciphertext, const u8 *src_plaintext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
	chacha20poly1305_encrypt(
        dst_ciphertext, 
        src_plaintext, 
        src_len, hash, 
        NOISE_HASH_LEN,
		0 /* Always zero for Noise_IK */, key);

	update_transcript(hash, dst_ciphertext, noise_encrypted_len(src_len));
}
//server side
bool message_decrypt(u8 *dst_plaintext, const u8 *src_ciphertext, size_t src_len, u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 hash[NOISE_HASH_LEN])
{
    if (!chacha20poly1305_decrypt(
        dst_plaintext, 
        src_ciphertext, 
        src_len,
		hash, 
        NOISE_HASH_LEN,
		0 /* Always zero for Noise_IK */, 
        key))
	{ return false; }

	update_transcript(hash, src_ciphertext, src_len); //H3
	return true;
}

/*
    Tai64N    
    THis function was taken from wireguard source code
    https://github.com/WireGuard/wireguard-linux/blob/stable/drivers/net/wireguard/noise.c
*/
void tai64n_now(u8 output[NOISE_TIMESTAMP_LEN])
{
	struct timespec64 now;
	ktime_get_real_ts64(&now);
	/* In order to prevent some sort of infoleak from precise timers, we
	 * round down the nanoseconds part to the closest rounded-down power of
	 * two to the maximum initiations per second allowed anyway by the
	 * implementation.
	 */
	now.tv_nsec = ALIGN_DOWN(now.tv_nsec,
		rounddown_pow_of_two(NSEC_PER_SEC / INITIATIONS_PER_SECOND));
	/* https://cr.yp.to/libtai/tai64.html */
	*(__be64 *)output = cpu_to_be64(0x400000000000000aULL + now.tv_sec);
	*(__be32 *)(output + sizeof(__be64)) = cpu_to_be32(now.tv_nsec);
}

/*
	Message 2: e, ee, se, psk
*/
//e
//same function as message1
//ee
bool __must_check message_ee (const u8 ephemeral_public[NOISE_PUBLIC_KEY_LEN], const u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN] ,u8 chaining_key[NOISE_HASH_LEN]){
	//C5
	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];
	//diffie hellman share secret
	if (!curve25519(dh_calculation, ephemeral_private, ephemeral_public)){
		return false;
	}
    kdf(
        chaining_key, //C2
        NULL, //k1
        NULL, 
        dh_calculation, 
        NOISE_HASH_LEN,
        0, 
        0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);

	return true;
}

//se
bool __must_check message_se(const u8 ephemeral_private_key[NOISE_PUBLIC_KEY_LEN], const u8 remote_static[NOISE_PUBLIC_KEY_LEN] ,u8 chaining_key[NOISE_HASH_LEN]){
	//C1
	u8 dh_calculation[NOISE_PUBLIC_KEY_LEN];
	//diffie hellman share secret
	if (!curve25519(dh_calculation, ephemeral_private_key, remote_static)){
		return false;
	}
	kdf(
        chaining_key, //C2
        NULL, //k1
        NULL, 
        dh_calculation, 
        NOISE_HASH_LEN,
        0, 
        0, NOISE_PUBLIC_KEY_LEN, chaining_key);
	memzero_explicit(dh_calculation, NOISE_PUBLIC_KEY_LEN);

	return true;
}
//psk
void mix_psk(u8 psk[NOISE_SYMMETRIC_KEY_LEN], u8 key[NOISE_SYMMETRIC_KEY_LEN], u8 chaining_key[NOISE_HASH_LEN], u8 hash[NOISE_HASH_LEN])
{
	u8 pi[NOISE_HASH_LEN];
	//expand 
	kdf(
        chaining_key, //C2
        pi, 
        key, //key
        psk, 
        NOISE_HASH_LEN,
        NOISE_HASH_LEN,
        NOISE_SYMMETRIC_KEY_LEN, 
        NOISE_SYMMETRIC_KEY_LEN, chaining_key);
	
	update_transcript(hash, pi, NOISE_HASH_LEN); //H6

}

//derivate keys
void derive_keys(u8 first_key[NOISE_SYMMETRIC_KEY_LEN], u8 second_key[NOISE_SYMMETRIC_KEY_LEN], const u8 chaining_key[NOISE_HASH_LEN])
{
	kdf(
        first_key,
        second_key,
        NULL,NULL,
        NOISE_SYMMETRIC_KEY_LEN, NOISE_SYMMETRIC_KEY_LEN,
        0,0,
        chaining_key
    );
}


