// SPDX-License-Identifier: GPL-2.0
/* NOISE: comment to address */
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

/* NOISE: comment to address */
static struct key *noise_keyring;

/* NOISE: comment to address */
static void noise_clients_destroy(void);

/* NOISE: comment to address */
static int keyring_serial;
module_param(keyring_serial, int, 0444);
MODULE_PARM_DESC(keyring_serial,
		 "Serial of the kernel keyring holding the Noise secrets");

/* NOISE: comment to address */
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

/* NOISE: comment to address */
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

/* NOISE: comment to address */
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

/* NOISE: comment to address */
int noise_psk_lookup(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
		     u8 psk[NOISE_SYMMETRIC_KEY_LEN])
{
	char desc[sizeof("noise:psk:") + 2 * NOISE_PUBLIC_KEY_LEN];

	scnprintf(desc, sizeof(desc), "noise:psk:%*phN",
		  NOISE_PUBLIC_KEY_LEN, pubkey);
	return noise_key_lookup(desc, psk, NOISE_SYMMETRIC_KEY_LEN);
}
EXPORT_SYMBOL(noise_psk_lookup);

/* NOISE: comment to address */
struct noise_client {
	u8			static_public[NOISE_PUBLIC_KEY_LEN];
	u8			last_timestamp[NOISE_TIMESTAMP_LEN];
	spinlock_t		lock;
	struct hlist_node	node;
};

#define NOISE_CLIENT_HASH_BITS	8
static DEFINE_HASHTABLE(noise_clients, NOISE_CLIENT_HASH_BITS);
static DEFINE_SPINLOCK(noise_clients_lock);

/* NOISE: comment to address */
static struct noise_client *noise_client_find(const u8 *pubkey, u32 key)
{
	struct noise_client *cl;

	hash_for_each_possible(noise_clients, cl, node, key) {
		if (memcmp(cl->static_public, pubkey, NOISE_PUBLIC_KEY_LEN) == 0)
			return cl;
	}
	return NULL;
}

/* NOISE: comment to address */
static struct noise_client *noise_client_get(const u8 *pubkey)
{
	u32 key = jhash(pubkey, NOISE_PUBLIC_KEY_LEN, 0);
	struct noise_client *cl, *new;

	spin_lock(&noise_clients_lock);
	cl = noise_client_find(pubkey, key);
	spin_unlock(&noise_clients_lock);
	if (cl)
		return cl;

	new = kzalloc_obj(*new, GFP_KERNEL);
	if (!new)
		return NULL;
	memcpy(new->static_public, pubkey, NOISE_PUBLIC_KEY_LEN);
	spin_lock_init(&new->lock);

	spin_lock(&noise_clients_lock);
	cl = noise_client_find(pubkey, key);
	if (cl) {
		spin_unlock(&noise_clients_lock);
		kfree(new);
		return cl;
	}
	hash_add(noise_clients, &new->node, key);
	spin_unlock(&noise_clients_lock);
	return new;
}

/* NOISE: comment to address */
bool noise_client_check_ts(const u8 pubkey[NOISE_PUBLIC_KEY_LEN],
			   const u8 timestamp[NOISE_TIMESTAMP_LEN])
{
	struct noise_client *cl = noise_client_get(pubkey);
	bool ok;

	if (!cl)
		return false;

	spin_lock(&cl->lock);
	if (memcmp(timestamp, cl->last_timestamp, NOISE_TIMESTAMP_LEN) <= 0) {
		ok = false;
	} else {
		memcpy(cl->last_timestamp, timestamp, NOISE_TIMESTAMP_LEN);
		ok = true;
	}
	spin_unlock(&cl->lock);
	return ok;
}
EXPORT_SYMBOL(noise_client_check_ts);

/* NOISE: comment to address */
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
