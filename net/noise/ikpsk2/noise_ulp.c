// SPDX-License-Identifier: GPL-2.0
/*
 *	NFSv4 Data-In-Flight Encryption over Noise protocol framework
 *
 *	Socket-encryption layer ("ULP-style"): once the IKpsk2 handshake has
 *	derived the session keys, the socket's proto send/recv operations are
 *	swapped so that the *entire* TCP byte stream is transparently sealed and
 *	opened. The upper layer (SUNRPC) then writes plaintext RPC records as
 *	usual and the socket encrypts them - the converse of the previous
 *	payload model (which sealed each RPC record at the RPC layer).
 *
 *	NOTE: This is the socket-encryption variant. It is UNTESTED in this tree;
 *	it must be built and smoke-tested. See the verification checklist at the
 *	end of the commit / FUNCS.md.
 *
 *	Axel Biegalski - HWU MSc project
 */
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/uio.h>
#include <linux/string.h>
#include <linux/unaligned.h>
#include <net/sock.h>
#include <net/tcp.h>
#include <net/inet_connection_sock.h>
#include <net/noise.h>

/* Maximum plaintext carried in one sealed stream record. */
#define NOISE_ULP_MAX_PT	16384u

/*
 * Per-socket Noise socket-encryption context. Hung off
 * inet_csk(sk)->icsk_ulp_data while the ULP is installed.
 */
struct noise_ulp_ctx {
	struct proto		*base;	/* original sk_prot (TCP) */
	struct proto		prot;	/* our overridden copy installed on sk */
	struct noise_peer	*peer;	/* keys/counters; owned by the transport */
	struct noise_rx		rx;	/* receive reassembly + decrypted buffer */
};

static inline struct noise_ulp_ctx *noise_ulp_ctx(struct sock *sk)
{
	return (struct noise_ulp_ctx *)inet_csk(sk)->icsk_ulp_data;
}

/* Read up to @len ciphertext bytes from the lower (base) socket. */
static int noise_ulp_read_some(struct sock *sk, struct noise_ulp_ctx *ctx,
			       u8 *buf, size_t len, int flags)
{
	struct kvec iov = { .iov_base = buf, .iov_len = len };
	struct msghdr m = { };

	iov_iter_kvec(&m.msg_iter, ITER_DEST, &iov, 1, len);
	return ctx->base->recvmsg(sk, &m, len, flags);
}

/*
 * Reassemble + decrypt the next sealed record into ctx->rx.pt.
 * Resumable across partial reads (state persists in ctx->rx).
 * Returns 1 when a plaintext record is ready, 0 on EOF, <0 on error/EAGAIN.
 */
static int noise_ulp_rx_fill(struct sock *sk, struct noise_ulp_ctx *ctx,
			     int flags)
{
	struct noise_rx *rx = &ctx->rx;
	int n, ptlen;

	while (rx->hdr_got < NOISE_REC_LEN_SIZE) {
		n = noise_ulp_read_some(sk, ctx, rx->hdr + rx->hdr_got,
					NOISE_REC_LEN_SIZE - rx->hdr_got, flags);
		if (n <= 0)
			return n;
		rx->hdr_got += n;
	}
	if (!rx->body) {
		rx->body_len = get_unaligned_be32(rx->hdr);
		if (rx->body_len < NOISE_REC_CTR_SIZE + NOISE_AUTHTAG_LEN ||
		    rx->body_len > NOISE_ULP_MAX_PT + NOISE_REC_OVERHEAD) {
			pr_warn_ratelimited("noise-ulp: implausible frame length %u\n",
					    rx->body_len);
			return -EMSGSIZE;
		}
		rx->body = kmalloc(rx->body_len, GFP_KERNEL);
		if (!rx->body)
			return -ENOMEM;
		rx->body_got = 0;
	}
	while (rx->body_got < rx->body_len) {
		n = noise_ulp_read_some(sk, ctx, rx->body + rx->body_got,
					rx->body_len - rx->body_got, flags);
		if (n <= 0)
			return n;
		rx->body_got += n;
	}
	rx->pt = kmalloc(rx->body_len, GFP_KERNEL);
	if (!rx->pt)
		return -ENOMEM;
	ptlen = noise_record_open(ctx->peer, rx->body, rx->body_len, rx->pt);
	kfree(rx->body);
	rx->body = NULL;
	rx->hdr_got = 0;
	rx->body_got = 0;
	if (ptlen < 0) {
		kfree(rx->pt);
		rx->pt = NULL;
		return -EBADMSG;
	}
	rx->pt_len = ptlen;
	rx->pt_pos = 0;
	return 1;
}

/* proto->recvmsg: serve the caller from decrypted plaintext records. */
static int noise_ulp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len,
			     int flags)
{
	struct noise_ulp_ctx *ctx = noise_ulp_ctx(sk);
	struct noise_rx *rx = &ctx->rx;
	size_t copied = 0;
	int r;

	while (iov_iter_count(&msg->msg_iter)) {
		if (rx->pt_pos < rx->pt_len) {
			size_t n = copy_to_iter(rx->pt + rx->pt_pos,
						rx->pt_len - rx->pt_pos,
						&msg->msg_iter);
			rx->pt_pos += n;
			copied += n;
			if (rx->pt_pos >= rx->pt_len) {
				kfree(rx->pt);
				rx->pt = NULL;
				rx->pt_len = rx->pt_pos = 0;
			}
			continue;
		}
		r = noise_ulp_rx_fill(sk, ctx, flags);
		if (r <= 0) {
			if (copied)
				break;
			if (r == 0)
				return 0;	/* EOF */
			/* -EAGAIN: state kept in ctx->rx, caller retries.
			 * framing/decrypt error: report it; the connection
			 * will be torn down and re-handshaked.
			 */
			return r;
		}
	}
	return copied;
}

/* proto->sendmsg: seal the plaintext byte stream in chunks, write to TCP. */
static int noise_ulp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
{
	struct noise_ulp_ctx *ctx = noise_ulp_ctx(sk);
	u8 *pt = NULL, *frame = NULL;
	size_t left = size;
	int ret;

	pt = kmalloc(NOISE_ULP_MAX_PT, GFP_KERNEL);
	frame = kmalloc(NOISE_ULP_MAX_PT + NOISE_REC_OVERHEAD, GFP_KERNEL);
	if (!pt || !frame) {
		ret = -ENOMEM;
		goto out;
	}

	while (left) {
		size_t chunk = min_t(size_t, left, NOISE_ULP_MAX_PT);
		int wirelen, sent = 0;

		if (copy_from_iter(pt, chunk, &msg->msg_iter) != chunk) {
			ret = -EFAULT;
			goto out;
		}
		wirelen = noise_record_seal(ctx->peer, frame, pt, chunk);
		if (wirelen < 0) {
			ret = wirelen;
			goto out;
		}
		/* Blocking, all-or-nothing send of one sealed record. A failure
		 * here means the connection is broken: report the error so RPC
		 * tears it down and retransmits the whole request after a fresh
		 * handshake (a half-written record dies with the connection).
		 */
		while (sent < wirelen) {
			struct kvec siov = { .iov_base = frame + sent,
					     .iov_len = wirelen - sent };
			struct msghdr sm = { };
			int n;

			iov_iter_kvec(&sm.msg_iter, ITER_SOURCE, &siov, 1,
				      wirelen - sent);
			n = ctx->base->sendmsg(sk, &sm, wirelen - sent);
			if (n <= 0) {
				ret = n ? n : -EPIPE;
				goto out;
			}
			sent += n;
		}
		left -= chunk;
	}
	ret = size;

	/* Rekey: once the keypair crosses a threshold, drop the connection so
	 * SUNRPC reconnects and re-handshakes (fresh keys). Replaces the old
	 * RPC-layer rekey trigger.
	 */
	if (noise_peer_should_rekey(ctx->peer))
		ctx->base->shutdown(sk, SEND_SHUTDOWN);
out:
	kfree(pt);
	kfree(frame);
	return ret;
}

/* proto->close: restore the base proto, free our state, then close. */
static void noise_ulp_close(struct sock *sk, long timeout)
{
	struct noise_ulp_ctx *ctx = noise_ulp_ctx(sk);
	struct proto *base = ctx->base;

	WRITE_ONCE(sk->sk_prot, base);
	inet_csk(sk)->icsk_ulp_data = NULL;
	noise_rx_reset(&ctx->rx);
	kfree(ctx);
	base->close(sk, timeout);
}

/**
 * noise_ulp_install - turn @sock into a Noise-encrypting socket
 * @sock: the connected TCP socket (handshake already completed)
 * @peer: per-connection Noise state holding the derived session keys
 *
 * After this call every send/recv on @sock is transparently sealed/opened.
 * @peer is referenced, not owned (freed by the transport on teardown).
 */
int noise_ulp_install(struct socket *sock, struct noise_peer *peer)
{
	struct sock *sk = sock->sk;
	struct noise_ulp_ctx *ctx;

	if (!sk)
		return -ENOTCONN;

	ctx = kzalloc(sizeof(*ctx), GFP_KERNEL);
	if (!ctx)
		return -ENOMEM;

	ctx->peer = peer;
	ctx->base = sk->sk_prot;
	ctx->prot = *sk->sk_prot;	/* inherit everything from TCP ... */
	ctx->prot.sendmsg = noise_ulp_sendmsg;	/* ... override the data path */
	ctx->prot.recvmsg = noise_ulp_recvmsg;
	ctx->prot.close   = noise_ulp_close;

	lock_sock(sk);
	inet_csk(sk)->icsk_ulp_data = ctx;
	smp_store_release(&sk->sk_prot, &ctx->prot);
	release_sock(sk);
	return 0;
}
EXPORT_SYMBOL(noise_ulp_install);
