#ifndef NOISE_TRANSPORT_H
#define NOISE_TRANSPORT_H

#include "noise_crypto.h"

enum transport_limits {
	REJECT_AFTER_MESSAGES = U64_MAX - 16
};

bool __must_check noise_transport_encrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 *counter);
bool __must_check noise_transport_decrypt(struct noise_peer *peer, u8 *dst, const u8 *src, size_t src_len, u64 counter);

#endif
