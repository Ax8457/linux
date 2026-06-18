#ifndef HANDSHAKE_H
#define HANDSHAKE_H

#include "noise_crypto.h"

bool noise_handshake_create_initiation(struct ikpsk2_msg1 *m1, struct noise_handshake *handshake);
bool handshake_consume_initiation(struct ikpsk2_msg1 *m1, struct noise_peer *peer);
bool handshake_create_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
bool handshake_consume_response(struct ikpsk2_msg2 *m2, struct noise_peer *peer);
bool begin_session(struct noise_peer *peer);

#endif
