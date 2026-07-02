// SPDX-License-Identifier: GPL-2.0
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Key management.
 *
 *	A kernel-held keyring ".noise" holds the Noise long-term secrets as
 *	"user" keys, provisioned from userspace with keyctl(1):
 *
 *	  noise:priv:server          server static private scalar (32 bytes)
 *	  noise:priv:client          client static private scalar (32 bytes)
 *	  noise:pub:server           server static public key     (32 bytes)
 *	  noise:psk:<client-pub-hex> pre-shared key for that client(32 bytes)
 *
 *	The PSK is keyed by the *client* static public key (lowercase hex, no
 *	separator), exactly like WireGuard keys a peer's preshared key by its
 *	public key: the responder looks it up once msg1 reveals the client
 *	static key, and the initiator looks up the same description under its
 *	own public key. Replaces the previous hardcoded test keys.
 *
 *	Axel Biegalski - HWU MSc project
 */
#include <linux/module.h>
#include <linux/key.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/jhash.h>
#include <keys/user-type.h>

#include <net/noise.h>

/* kernel-held keyring; populated from userspace, searched by the handshake */
static struct key *noise_keyring;

/* free all per-client anti-replay records (defined below) */
static void noise_clients_destroy(void);

/* Serial of the keyring, exported read-only so userspace can target it:
 *   serial=$(cat /sys/module/noise_ikpsk2/parameters/keyring_serial)
 *   keyctl padd user "noise:priv:server" "$serial" < server.priv
 */
static int keyring_serial;
module_param(keyring_serial, int, 0444);
MODULE_PARM_DESC(keyring_serial,
		 "Serial of the kernel keyring holding the Noise secrets");

int ikpsk2_keyring_init(void)
{
	struct key *keyring;

	keyring = keyring_alloc(".noise",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, current_cred(),
			(KEY_POS_ALL & ~KEY_POS_SETATTR) |
			KEY_USR_VIEW | KEY_USR_READ |
			KEY_USR_WRITE | KEY_USR_SEARCH,
			KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	noise_keyring = keyring;
	keyring_serial = keyring->serial;
	return 0;
}
EXPORT_SYMBOL(ikpsk2_keyring_init);

void ikpsk2_keyring_exit(void)
{
	noise_clients_destroy();

	if (noise_keyring) {
		key_put(noise_keyring);
		noise_keyring = NULL;
		keyring_serial = 0;
	}
}
EXPORT_SYMBOL(ikpsk2_keyring_exit);

/*
 * noise_key_lookup - copy exactly @len bytes of the "user" key @desc into @out.
 * Returns 0 on success, -ENOKEY if absent, -EINVAL on a size mismatch.
 */
int noise_key_lookup(const char *desc, u8 *out, size_t len)
{
	const struct user_key_payload *up;
	key_ref_t kref;
	struct key *key;
	int ret = -ENOKEY;

	if (!noise_keyring)
		return -ENOKEY;

	kref = keyring_search(make_key_ref(noise_keyring, 1),
			      &key_type_user, desc, false);
	if (IS_ERR(kref))
		return -ENOKEY;
	key = key_ref_to_ptr(kref);

	down_read(&key->sem);
	up = user_key_payload_locked(key);
	if (!up)
		ret = -ENOKEY;
	else if (up->datalen != len)
		ret = -EINVAL;
	else {
		memcpy(out, up->data, len);
		ret = 0;
	}
	up_read(&key->sem);
	key_put(key);
	return ret;
}
EXPORT_SYMBOL(noise_key_lookup);

/*
 * noise_psk_lookup - fetch the pre-shared key associated with @pubkey.
 * The description is "noise:psk:<pubkey-as-lowercase-hex>".
 */
int noise_psk_lookup(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
		     u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	char desc[sizeof("noise:psk:") + 2 * NOISE_PUBLIC_KEY_LEN];

	scnprintf(desc, sizeof(desc), "noise:psk:%*phN",
		  NOISE_PUBLIC_KEY_LEN, pubkey);
	return noise_key_lookup(desc, psk, NOISE_SYMMETRIC_KEY_LEN);
}
EXPORT_SYMBOL(noise_psk_lookup);

/*
 * Per-client persistent state (anti-replay).
 *
 * The handshake struct is per-connection and freshly zeroed each time, so it
 * cannot remember a client's last initiation timestamp across connections. This
 * hashtable, keyed by the client static public key, holds that persistent state
 * so a replayed msg1 arriving on a *new* connection can be detected.
 *
 * Records are created lazily on first authenticated contact (after the PSK
 * check, so unknown/forged pubkeys cannot pollute the table) and freed at
 * module unload. Each record's spinlock makes the timestamp compare-and-update
 * atomic against concurrent handshakes for the same client.
 */
struct noise_client {
	u8			static_public[NOISE_PUBLIC_KEY_LEN];	/* hash key   */
	u8			last_timestamp[NOISE_TIMESTAMP_LEN];	/* TAI64N     */
	spinlock_t		lock;					/* CAS on ts  */
	struct hlist_node	node;
};

#define NOISE_CLIENT_HASH_BITS	8
static DEFINE_HASHTABLE(noise_clients, NOISE_CLIENT_HASH_BITS);
static DEFINE_SPINLOCK(noise_clients_lock);	/* protects table insert/lookup */

/* find an existing record; caller holds noise_clients_lock */
static struct noise_client *noise_client_find(const u8 *pubkey, u32 key)
{
	struct noise_client *cl;

	hash_for_each_possible(noise_clients, cl, node, key) {
		if (memcmp(cl->static_public, pubkey, NOISE_PUBLIC_KEY_LEN) == 0)
			return cl;
	}
	return NULL;
}

/* find or create the record for @pubkey (NULL only on allocation failure) */
static struct noise_client *noise_client_get(const u8 *pubkey)
{
	u32 key = jhash(pubkey, NOISE_PUBLIC_KEY_LEN, 0);
	struct noise_client *cl, *new;

	spin_lock(&noise_clients_lock);
	cl = noise_client_find(pubkey, key);
	spin_unlock(&noise_clients_lock);
	if (cl)
		return cl;

	/* allocate outside the table lock (may sleep in process context) */
	new = kzalloc(sizeof(*new), GFP_KERNEL);
	if (!new)
		return NULL;
	memcpy(new->static_public, pubkey, NOISE_PUBLIC_KEY_LEN);
	spin_lock_init(&new->lock);

	spin_lock(&noise_clients_lock);
	cl = noise_client_find(pubkey, key);	/* lost a race? use the winner */
	if (cl) {
		spin_unlock(&noise_clients_lock);
		kfree(new);
		return cl;
	}
	hash_add(noise_clients, &new->node, key);
	spin_unlock(&noise_clients_lock);
	return new;
}

/*
 * noise_client_check_ts - anti-replay check for a msg1 initiation timestamp.
 *
 * MUST be called only after the client is authenticated (its PSK was found),
 * so forged pubkeys cannot create records. Returns true and advances the stored
 * timestamp iff @timestamp is strictly newer than the last one accepted from
 * this client; returns false for a replayed/stale (or, fail-safe, unstorable)
 * initiation. TAI64N is big-endian, so memcmp() gives chronological order.
 */
bool noise_client_check_ts(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 timestamp[NOISE_TIMESTAMP_LEN])
{
	struct noise_client *cl = noise_client_get(pubkey);
	bool ok;

	if (!cl)
		return false;			/* alloc failure -> reject (fail safe) */

	spin_lock(&cl->lock);
	if (memcmp(timestamp, cl->last_timestamp, NOISE_TIMESTAMP_LEN) <= 0) {
		ok = false;			/* replay / stale */
	} else {
		memcpy(cl->last_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
		ok = true;			/* newer -> accept + advance */
	}
	spin_unlock(&cl->lock);
	return ok;
}
EXPORT_SYMBOL(noise_client_check_ts);

/* free all per-client records; called from module teardown */
static void noise_clients_destroy(void)
{
	struct noise_client *cl;
	struct hlist_node *tmp;
	int bkt;

	spin_lock(&noise_clients_lock);
	hash_for_each_safe(noise_clients, bkt, tmp, cl, node) {
		hash_del(&cl->node);
		kfree(cl);
	}
	spin_unlock(&noise_clients_lock);
}
