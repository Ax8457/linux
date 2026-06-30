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
#include <keys/user-type.h>

#include <net/noise.h>

/* kernel-held keyring; populated from userspace, searched by the handshake */
static struct key *noise_keyring;

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
