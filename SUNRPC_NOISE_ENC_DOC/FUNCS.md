# Noise / SUNRPC function inventory

List of functions **added** or **modified** in the Linux kernel tree for the
NFSv4-over-Noise (IKpsk2) data-in-transit encryption work.

---

## 1. Noise package (shared core) — `net/noise/ikpsk2/`

Generic, side-agnostic building blocks called by both the client and the server.

### 1.1 Module / init — `noise_main.c`, `noise_crypto.c`
| Function | Description |
|----------|-------------|
| `noise_init` / `noise_exit` | Module load/unload entry points for the Noise package. |
| `ikpsk2_noise_init` | One-time init of the Noise package (constants / handshake name). |

### 1.2 Handshake state machine — `handshake.c`
| Function | Description |
|----------|-------------|
| `noise_handshake_create_initiation` | Initiator: build handshake message 1 (`ikpsk2_msg1`). |
| `handshake_consume_initiation` | Responder: validate message 1, recover the peer static key. |
| `handshake_create_response` | Responder: build handshake message 2 (`ikpsk2_msg2`). |
| `handshake_consume_response` | Initiator: validate message 2. |
| `begin_session` | Derive the directional session keys, reset counters, stamp the keypair birthdate. |

### 1.3 Cryptographic helpers — `noise_crypto.c`
| Function | Description |
|----------|-------------|
| `init_handshake` | Initialise the chaining key and transcript hash. |
| `update_transcript` | Mix data into the running handshake transcript hash. |
| `hmac` / `kdf` | HMAC and HKDF (BLAKE2s) key-derivation primitives. |
| `message_e` | Mix an ephemeral public key into the transcript/chaining key. |
| `mix_dh` | Curve25519 DH and mix the shared secret into the chaining key. |
| `message_encrypt` / `message_decrypt` | AEAD (ChaCha20-Poly1305) of handshake fields, transcript as AAD. |
| `message_ee` / `message_se` | The `ee` and `se` DH mixes of the response. |
| `mix_psk` | Mix the pre-shared key into the chaining key (the "psk2" step). |
| `derive_keys` | Final HKDF producing the two transport session keys. |
| `tai64n_now` | Produce a  TAI64N timestamp for the initiation. |

### 1.4 Transport phase — `noise_transport.c`
| Function | Description |
|----------|-------------|
| `noise_transport_encrypt` | AEAD-seal one buffer; allocate the counter/nonce. |
| `noise_transport_decrypt` | AEAD-open one buffer for a given counter. |
| `noise_record_seal` | Frame + encrypt one record: `[len][counter][ciphertext+tag]`. |
| `noise_record_open` | Parse + decrypt one record; monotonic anti-replay on the counter. |
| `noise_rx_reset` | Free and zero the per-connection receive reassembly state. |
| `noise_peer_should_rekey` | True once the keypair hits the message/time rekey threshold. |

### 1.5 Socket encryption (ULP) — `noise_ulp.c`

Socket-level transform installed after the handshake: swaps the socket's proto
send/recv so the *whole* TCP byte stream is sealed/opened transparently (RPC
writes plaintext). This is the socket-encryption model; it supersedes the
RPC-layer payload hooks (now bypassed, `noise_active` left false).

| Function | Description |
|----------|-------------|
| `noise_ulp_install` | After the handshake, swap `sk_prot` send/recv to the Noise versions. |
| `noise_ulp_sendmsg` | proto send: chunk the plaintext stream and `noise_record_seal` each chunk; rekey trigger. |
| `noise_ulp_recvmsg` | proto recv: serve the caller from decrypted records. |
| `noise_ulp_rx_fill` | Reassemble + `noise_record_open` the next record (reuses `noise_rx`). |
| `noise_ulp_read_some` | Read ciphertext from the lower (base) socket. |
| `noise_ulp_close` | Restore the base proto, free the per-socket context, then close. |

---

## 2. Client side — `net/sunrpc/xprtsock.c`

### 2.1 Transport registration / connection setup
| Function | Description |
|----------|-------------|
| `xs_setup_tcp_noise` | Transport-class factory: build the `sock_xprt`, arm the Noise connect worker. |
| `xs_tcp_noise_setup_socket` | Connect worker: create the socket, TCP connect, then run the handshake. |
| `xs_tcp_noise_finish_connecting` | Perform the TCP connect on the lower socket. |
| `xs_tcp_noise_state_change` | Socket state callback: signal TCP ESTABLISHED to the connect worker. |
| `xs_tcp_state_change` (MOD) | TCP state handling extended to complete the handshake-done event. |
| `xs_data_ready` (MOD) | Receive callback; respects the handshake/ignore-recv state. |

### 2.2 Handshake (initiator)
| Function | Description |
|----------|-------------|
| `xs_noise_handshake_sync` | Drive the IKpsk2 initiator exchange (msg1 out, msg2 in), then derive keys. |
| `xs_noise_setup_keys` | Install the client static identity and pre-shared key into the peer. |
| `xs_noise_send` | Send exactly N bytes (a handshake message) over the lower socket. |
| `xs_noise_recv` | Block until exactly N bytes (a handshake message) are received. |

### 2.3 Transport phase (send / receive / rekey)
| Function | Description |
|----------|-------------|
| `xs_tcp_send_request` (MOD) | Send path; routes through the Noise record sealer when active, triggers rekey. |
| `xs_noise_send_record` | Seal one RPC record and write it to the socket. |
| `xs_noise_linearize` | Flatten the scattered `xdr_buf` (marker + head + pages + tail) into one buffer. |
| `xs_noise_send_all` | Blocking loop to write all wire bytes. |
| `xs_sock_recvmsg` (MOD) | Receive path; serves decrypted records when Noise is active. |
| `xs_noise_recvmsg` | Serve the stream reader from decrypted plaintext records. |
| `xs_noise_rx_fill` | Reassemble + decrypt the next record into the receive state. |
| `xs_noise_read_some` | Non-blocking read of up to N bytes from the socket. |
| `xs_noise_bc_send` | Backchannel send path sealed with Noise (callback direction). |

---

## 3. Server side — `net/sunrpc/svcsock.c`

### 3.1 Connection acceptance / handshake trigger
| Function | Description |
|----------|-------------|
| `svc_tcp_accept` (MOD) | Accept a connection; when `svc_noise` is set, flag it for the Noise handshake. |
| `svc_data_ready` (MOD) | Receive callback; suppresses RPC enqueue while the handshake is pending. |
| `svc_tcp_handshake` (MOD) | Handshake entry; routes to the Noise responder instead of the TLS upcall. |

### 3.2 Handshake (responder)
| Function | Description |
|----------|-------------|
| `svc_noise_handshake` | Run the IKpsk2 responder (msg1 in, msg2 out), then derive keys. |
| `svc_noise_setup_keys` | Install the server static identity and pre-shared key into the peer. |
| `svc_noise_send` | Send exactly N bytes (a handshake message) over the socket. |
| `svc_noise_recv` | Block until exactly N bytes (a handshake message) are received. |

### 3.3 Transport phase (receive / send / rekey)
| Function | Description |
|----------|-------------|
| `svc_tcp_sock_recvmsg` (MOD) | Receive path; serves decrypted records when Noise is active. |
| `svc_noise_recvmsg` | Serve the server stream reader from decrypted records. |
| `svc_noise_rx_fill` | Reassemble + decrypt the next record into the receive state. |
| `svc_noise_read_some` | Non-blocking read of up to N bytes from the socket. |
| `svc_noise_sendmsg` | Seal one reply record and write it; triggers rekey (drops the connection). |
| `svc_noise_linearize` | Flatten the reply `xdr_buf` into one contiguous buffer. |
| `svc_noise_send_all` | Blocking loop to write all wire bytes. |

---

## 4. Configuration / selection (not functions)

| Item | Side | Description |
|------|------|-------------|
| `xprtsec=noise` mount option | client | Parsed in `fs/nfs/fs_context.c`; selects the Noise transport. |
| `svc_noise` module parameter | server | `net/sunrpc/svcsock.c`; enables the Noise responder on accepted connections. |
| `RPC_XPRTSEC_NOISE` / `XPRT_TRANSPORT_TCP_NOISE` | both | New policy / transport identifiers wiring the option to the transport class. |
