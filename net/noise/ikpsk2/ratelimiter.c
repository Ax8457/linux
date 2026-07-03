// SPDX-License-Identifier: GPL-2.0
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Handshake rate limiter.
 *
 *	Per-source-IP token bucket on handshake initiations, so a flood from one
 *	source cannot exhaust the responder's handshake workqueue / CPU. Inspired
 *	by WireGuard's ratelimiter.c, deliberately simplified:
 *
 *	  - single global spinlock + one hashtable + a periodic GC of idle
 *	    entries (no per-CPU mempool / RCU fast path): Noise handshakes are far
 *	    rarer than WireGuard data packets, so lock contention is a non-issue;
 *	  - keyed by the real peer address (v4 /32, v6 /64): over TCP the 3-way
 *	    handshake already proves the source, so no anti-spoofing hashing is
 *	    needed.
 *
 *	Token bucket: each source accrues RL_PACKET_COST ns of budget per allowed
 *	initiation, refilled with elapsed time up to a small burst.
 *
 *	Axel Biegalski - HWU MSc project
 */
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/slab.h>
#include <linux/ktime.h>
#include <linux/minmax.h>
#include <linux/workqueue.h>
#include <linux/jiffies.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/unaligned.h>

#include <net/noise.h>

/* token-bucket parameters (all in nanoseconds of budget) */
#define RL_PACKETS_PER_SECOND	INITIATIONS_PER_SECOND		/* reuse the 50 */
#define RL_BURST		5
#define RL_PACKET_COST		(NSEC_PER_SEC / RL_PACKETS_PER_SECOND)
#define RL_TOKEN_MAX		(RL_PACKET_COST * RL_BURST)

/* garbage collection: purge entries idle longer than the TTL, once per tick */
#define RL_ENTRY_TTL_NS		(2ULL * NSEC_PER_SEC)
#define RL_GC_INTERVAL		HZ

#define RL_HASH_BITS		10		/* 1024 buckets */

struct rl_entry {
	u64			key;		/* packed source address    */
	u64			last_ns;	/* last refill timestamp    */
	u64			tokens;		/* available budget (ns)    */
	struct hlist_node	node;
};

static DEFINE_HASHTABLE(rl_table, RL_HASH_BITS);
static DEFINE_SPINLOCK(rl_lock);

static void rl_gc(struct work_struct *work);
static DECLARE_DELAYED_WORK(rl_gc_work, rl_gc);

/* pack a source address into a u64 lookup key: IPv4 /32 or IPv6 /64 */
static u64 rl_key(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET)
		return (u64)((const struct sockaddr_in *)sa)->sin_addr.s_addr;
	if (sa->sa_family == AF_INET6)
		return get_unaligned((const __be64 *)
			&((const struct sockaddr_in6 *)sa)->sin6_addr);
	return 0;	/* unknown family: all share one bucket */
}

/* caller holds rl_lock */
static struct rl_entry *rl_find(u64 key)
{
	struct rl_entry *e;

	hash_for_each_possible(rl_table, e, node, key)
		if (e->key == key)
			return e;
	return NULL;
}

/*
 * noise_ratelimiter_allow - token-bucket check for a handshake from @sa.
 * Returns true if within budget (proceed), false if the source is flooding
 * (drop). Fail-open on allocation failure so memory pressure never blocks a
 * legitimate client.
 */
bool noise_ratelimiter_allow(const struct sockaddr *sa)
{
	u64 now = ktime_get_coarse_boottime_ns();
	u64 key = rl_key(sa);
	struct rl_entry *e;
	u64 tokens;
	bool allow;

	spin_lock_bh(&rl_lock);
	e = rl_find(key);
	if (!e) {
		e = kzalloc(sizeof(*e), GFP_ATOMIC);
		if (!e) {
			spin_unlock_bh(&rl_lock);
			return true;		/* fail open */
		}
		e->key = key;
		e->last_ns = now;
		e->tokens = RL_TOKEN_MAX;
		hash_add(rl_table, &e->node, key);
	}

	/* refill with elapsed time, capped at the burst maximum */
	tokens = min_t(u64, RL_TOKEN_MAX, e->tokens + (now - e->last_ns));
	e->last_ns = now;
	if (tokens >= RL_PACKET_COST) {
		e->tokens = tokens - RL_PACKET_COST;
		allow = true;
	} else {
		e->tokens = tokens;
		allow = false;
	}
	spin_unlock_bh(&rl_lock);
	return allow;
}
EXPORT_SYMBOL(noise_ratelimiter_allow);

/* periodic purge of idle entries so the table cannot grow without bound */
static void rl_gc(struct work_struct *work)
{
	u64 now = ktime_get_coarse_boottime_ns();
	struct hlist_node *tmp;
	struct rl_entry *e;
	int bkt;

	spin_lock_bh(&rl_lock);
	hash_for_each_safe(rl_table, bkt, tmp, e, node) {
		if (now - e->last_ns > RL_ENTRY_TTL_NS) {
			hash_del(&e->node);
			kfree(e);
		}
	}
	spin_unlock_bh(&rl_lock);

	schedule_delayed_work(&rl_gc_work, RL_GC_INTERVAL);
}

void noise_ratelimiter_init(void)
{
	schedule_delayed_work(&rl_gc_work, RL_GC_INTERVAL);
}
EXPORT_SYMBOL(noise_ratelimiter_init);

void noise_ratelimiter_exit(void)
{
	struct hlist_node *tmp;
	struct rl_entry *e;
	int bkt;

	cancel_delayed_work_sync(&rl_gc_work);

	spin_lock_bh(&rl_lock);
	hash_for_each_safe(rl_table, bkt, tmp, e, node) {
		hash_del(&e->node);
		kfree(e);
	}
	spin_unlock_bh(&rl_lock);
}
EXPORT_SYMBOL(noise_ratelimiter_exit);
