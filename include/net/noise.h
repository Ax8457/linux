/* SPDX-License-Identifier: GPL-2.0 */
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Public API: handshake (Noise IKpsk2) and transport-phase
 *	encrypt/decrypt, for use by other in-kernel subsystems
 *	(e.g. SUNRPC/xprtsock).
 *
 *	Axel Biegalski - HWU MSc project
 */
#ifndef _NET_NOISE_H
#define _NET_NOISE_H

#include <linux/types.h>
#include <linux/atomic.h>
#include <linux/limits.h>

#include <crypto/curve25519.h>
#include <crypto/chacha20poly1305.h>
#include <crypto/blake2s.h>

#define noise_encrypted_len(plain_len) ((plain_len) + NOISE_AUTHTAG_LEN)

/*
 * Enums
 */
/* handshake states */
enum noise_handshake_state {
	HANDSHAKE_ZEROED,
	HANDSHAKE_CREATED_INITIATION,
	HANDSHAKE_CONSUMED_INITIATION,
	HANDSHAKE_CREATED_RESPONSE,
	HANDSHAKE_CONSUMED_RESPONSE
};

/* noise lengths */
enum noise_lengths {
	NOISE_PUBLIC_KEY_LEN = CURVE25519_KEY_SIZE,
	NOISE_SYMMETRIC_KEY_LEN = CHACHA20POLY1305_KEY_SIZE,
	NOISE_TIMESTAMP_LEN = sizeof(u64) + sizeof(u32),
	NOISE_AUTHTAG_LEN = CHACHA20POLY1305_AUTHTAG_SIZE,
	NOISE_HASH_LEN = BLAKE2S_HASH_SIZE
};

/* taken from wireguard */
enum limits {
	INITIATIONS_PER_SECOND = 50
};

/* transport-phase limits */
enum transport_limits {
	REJECT_AFTER_MESSAGES = U64_MAX - 16
};

/* rekey thresholds (forward secrecy).
 * Rekeying is implemented as a connection teardown + fresh handshake (reusing
 * the transport reconnect path), not an in-place key rotation. Whichever
 * threshold is crossed first triggers a reconnect, which re-derives keys on
 * both ends. REKEY_AFTER_MESSAGES is a high backstop (well below the hard
 * REJECT_AFTER_MESSAGES); REKEY_AFTER_TIME is the trigger that fires in
 * practice.
 */
enum rekey_limits {
	REKEY_AFTER_MESSAGES = 1ULL << 60,
	REKEY_AFTER_TIME = 360,	/* seconds (1 hour) */
};

/*
 * Message framing header (WireGuard-inspired).
 *
 * Every handshake message on the wire begins with this fixed 8-byte header so
 * the receiver can route it with a switch() on @type, exactly like WireGuard's
 * struct message_header / message_type. Unlike WireGuard (which owns its UDP
 * socket and so needs no magic), the Noise handshake shares the TCP port with
 * plaintext RPC and TLS, so a @magic is added: it lets the responder tell a
 * Noise initiation apart from an RPC record marker before touching any crypto.
 *
 * The header is framing only: it is NOT mixed into the Noise hash transcript,
 * so the handshake crypto is unchanged on both ends.
 */
#define NOISE_MSG_MAGIC		0x4E4F4953u	/* "NOIS" (big-endian on wire) */
#define NOISE_MSG_VERSION	1u

enum noise_message_type {
	NOISE_MSG_INVALID		= 0,
	NOISE_MSG_HANDSHAKE_INITIATION	= 1,	/* initiator -> responder (msg1) */
	NOISE_MSG_HANDSHAKE_RESPONSE	= 2,	/* responder -> initiator (msg2) */
	NOISE_MSG_HANDSHAKE_ERROR	= 3,	/* responder -> initiator (reject) */
};

struct noise_message_header {
	__be32	magic;		/* NOISE_MSG_MAGIC			*/
	u8	type;		/* enum noise_message_type		*/
	u8	version;	/* NOISE_MSG_VERSION			*/
	u8	reserved[2];	/* must be zero				*/
} __packed;

/*
 * Structs
 */
/* encrypt and decrypt data once the handshake is done */
struct noise_keypair {
	u8 sending_key[NOISE_SYMMETRIC_KEY_LEN];
	bool i_am_the_initiator;
	u8 receiving_key[NOISE_SYMMETRIC_KEY_LEN];
	atomic64_t sending_counter;
	u64 receiving_counter;
	/* seconds (ktime_get_seconds) at which this keypair was derived; used
	 * to bound the key lifetime for rekeying.
	 */
	u64 birthdate;
};

/* identity */
struct noise_identity {
	u8 static_public[NOISE_PUBLIC_KEY_LEN];
	u8 static_private[NOISE_PUBLIC_KEY_LEN];
};

/* noise handshake */
struct noise_handshake {
	/* handshake state */
	enum noise_handshake_state state;
	/* handshake infos */
	u8 hash_transcript[NOISE_HASH_LEN];
	u8 chaining_key[NOISE_HASH_LEN];
	/* remote identities */
	u8 remote_static[NOISE_PUBLIC_KEY_LEN];
	u8 remote_ephemeral[NOISE_PUBLIC_KEY_LEN];
	/* local ephemeral identity
	 * Public ephemeral not stored => scalar mult
	 */
	u8 ephemeral_private[NOISE_PUBLIC_KEY_LEN];
	/* timestamp message1 */
	u8 latest_timestamp[NOISE_TIMESTAMP_LEN];
	/* preshared key => ikpsk2 */
	u8 psk[NOISE_SYMMETRIC_KEY_LEN];
	/* pre computed dh(S_priv_i, S_pub_r) C3, k2 for initiator and
	 * diffie hellman equivalent for responder
	 */
	u8 precomputed_static_static[NOISE_PUBLIC_KEY_LEN];
	/* identity */
	struct noise_identity *static_identity;
};

struct noise_peer {
	/* after handshake => derive keys */
	struct noise_keypair symmetric_keys;
	/* handshake data */
	struct noise_handshake handshake;
};

/* handshake messages */
/* m1 i -> r */
struct ikpsk2_msg1 {
	struct noise_message_header header;	/* type = NOISE_MSG_HANDSHAKE_INITIATION */
	u8 unencrypted_ephemeral[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_static[NOISE_PUBLIC_KEY_LEN + NOISE_AUTHTAG_LEN];
	u8 encrypted_timestamp[NOISE_TIMESTAMP_LEN + NOISE_AUTHTAG_LEN];
} __packed;

/* m2 r -> i */
struct ikpsk2_msg2 {
	struct noise_message_header header;	/* type = NOISE_MSG_HANDSHAKE_RESPONSE */
	u8 ephemeral_public_key[NOISE_PUBLIC_KEY_LEN];
	u8 encrypted_empty[NOISE_AUTHTAG_LEN];
} __packed;

/* enc data */
struct data {
	size_t len;
	u8 enc_data[];
};

/*
 * Public API
 */
void ikpsk2_noise_init(void);

/* key management (net/noise/ikpsk2/noise_keys.c)
 *
 * A kernel-held keyring ".noise" holds the long-term secrets as "user" keys,
 * provisioned from userspace with keyctl(1). ikpsk2_keyring_init/exit() are
 * driven by the module load/unload; the lookups are used by the handshake.
 */
int ikpsk2_keyring_init(void);
void ikpsk2_keyring_exit(void);
/* copy exactly @len bytes of the "user" key @desc into @out (0 / -ENOKEY / -EINVAL) */
int noise_key_lookup(const char *desc, u8 *out, size_t len);
/* fetch the PSK keyed by @pubkey: description "noise:psk:<pubkey-lowercase-hex>" */
int noise_psk_lookup(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
		     u8 psk[NOISE_SYMMETRIC_KEY_LEN]);
/* anti-replay: true iff @timestamp is strictly newer than the last accepted for
 * @pubkey (advancing the stored value). Persistent across connections, keyed by
 * pubkey. Call only after the client is authenticated (PSK found).
 */
bool noise_client_check_ts(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 timestamp[NOISE_TIMESTAMP_LEN]);

/* message framing (net/noise/ikpsk2/handshake.c) */
/* stamp @hdr with the magic/version and the given message @type */
void noise_message_header_set(struct noise_message_header *hdr, u8 type);
/* validate magic/version/reserved and return the message type, or
 * NOISE_MSG_INVALID if the header is not a well-formed Noise message. The
 * analog of WireGuard's SKB_TYPE_LE32() dispatch key.
 */
enum noise_message_type noise_message_classify(const struct noise_message_header *hdr);

/* handshake (net/noise/ikpsk2/handshake.c) */
bool noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake);
bool handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer);
bool handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
bool handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
bool begin_session(struct noise_peer *peer);

/* transport phase (net/noise/ikpsk2/noise_transport.c) */
bool __must_check noise_transport_encrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 *counter);
bool __must_check noise_transport_decrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 counter);

/* true once the current keypair has reached a rekey threshold (message count or
 * age); the caller should drop the connection so a fresh handshake runs.
 */
bool noise_peer_should_rekey(struct noise_peer *peer);

/* socket-encryption ("ULP") install: after the handshake, swap @sock's proto
 * send/recv so the whole TCP byte stream is sealed/opened transparently. @peer
 * is referenced (keys/counters), not owned. (net/noise/ikpsk2/noise_ulp.c)
 */
struct socket;
int noise_ulp_install(struct socket *sock, struct noise_peer *peer);

/*
 * Transport-phase record framing (WireGuard-style explicit counter).
 *
 * On-wire layout of one sealed record:
 *	[ __be32 body_len ][ __le64 counter ][ ciphertext (plaintext + tag) ]
 * where body_len = NOISE_REC_CTR_SIZE + len(ciphertext).
 */
enum noise_record {
	NOISE_REC_LEN_SIZE = 4,				/* __be32 body length prefix */
	NOISE_REC_CTR_SIZE = 8,				/* __le64 counter (nonce)    */
	NOISE_REC_OVERHEAD = NOISE_REC_LEN_SIZE + NOISE_REC_CTR_SIZE + NOISE_AUTHTAG_LEN,
};

/* Per-connection receive reassembly state for sealed records. */
struct noise_rx {
	u8	hdr[NOISE_REC_LEN_SIZE];	/* length prefix being read   */
	u32	hdr_got;
	u8	*body;				/* [counter][ciphertext]      */
	u32	body_len;			/* expected, from hdr         */
	u32	body_got;
	u8	*pt;				/* decrypted plaintext        */
	u32	pt_len;
	u32	pt_pos;				/* bytes already consumed     */
};

/* seal @pt (@ptlen bytes) into @dst (>= ptlen + NOISE_REC_OVERHEAD); returns wire length */
int noise_record_seal(struct noise_peer *peer, u8 *dst, const u8 *pt, u32 ptlen);
/* open a frame body [counter][ciphertext] of @body_len bytes into @pt; returns plaintext length or <0 */
int noise_record_open(struct noise_peer *peer, const u8 *body, u32 body_len, u8 *pt);
void noise_rx_reset(struct noise_rx *rx);

#endif /* _NET_NOISE_H */
