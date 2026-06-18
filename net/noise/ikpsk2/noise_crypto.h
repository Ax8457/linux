#ifndef NOISE_CRYPTO_H
#define NOISE_CRYPTO_H

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

/*

#define BLAKE2S_HASH_SIZE 32
#define NOISE_PUBLIC_KEY_LEN 32
#define NOISE_SYMMETRIC_KEY_LEN 32
#define NOISE_TIMESTAMP_LEN 12
*/

/*
	Enums
*/
//handshake states
enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE,
	COMM
};
//noise length
enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};
//taken from wireguard
enum limits {
	INITIATIONS_PER_SECOND = 50
};

/*
	Structs
*/
//encrypt and decrypt data once the handshake is done 
struct noise_keypair {
	u8 sending_key[NOISE_SYMMETRIC_KEY_LEN];
	bool i_am_the_initiator;
	u8 receiving_key[NOISE_SYMMETRIC_KEY_LEN];
	atomic64_t sending_counter;
	u64 receiving_counter;
};
// identity
struct noise_identity {
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
};
//noise handshake
struct noise_handshake {
	//handshake state
	enum noise_handshake_state state;
	//handshake infos
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	//remote identities
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	//local ephemeral identity
	/*
	* Public ephemeral note stored => scalar mult
	*/
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	//timestamp message1
	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
	//preshared key => ikpsk2
	u8 psk[NOISE_SYMMETRIC_KEY_LEN];
	/* pre computed 
	* dh(S_priv_i, S_pub_r) C3, k2 for initiator and diffie hellman equivalent for responder
	*/
	u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];
	// identity
	struct noise_identity *static_identity;
	
}; 

struct noise_peer {
	//after handshake => derive keys
	struct noise_keypair symmetric_keys;    
	//handshake data
	struct noise_handshake handshake;
};

//handshake messages
//m1 i -> r
struct ikpsk2_msg1 {
    u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];                     
    u8 encrypted_static[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];                 
    u8 encrypted_timestamp[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN]; 
};
//m2 r -> i
struct ikpsk2_msg2 {
    u8 ephemeral_public_key[NOISE_PUBLIC_KEY_LEN];                     
    u8 encrypted_empty[NOISE_AUTHTAG_LEN];
};
//enc data
struct data{
	size_t len;
	u8 enc_data[];
};

void ikpsk2_noise_init(void);
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

bool __must_check noise_transport_encrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 *counter);
bool __must_check noise_transport_decrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 counter);

#endif
