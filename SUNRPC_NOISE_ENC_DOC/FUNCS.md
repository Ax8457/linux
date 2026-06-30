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
| `noise_handshake_create_initiation` | Initiator: build handshake message 1 (`ikpsk2_msg1`); stamps the framing header with `NOISE_MSG_HANDSHAKE_INITIATION`. |
| `handshake_consume_initiation` | Responder: validate message 1, recover the peer static key. |
| `handshake_create_response` | Responder: build handshake message 2 (`ikpsk2_msg2`); stamps the framing header with `NOISE_MSG_HANDSHAKE_RESPONSE`. |
| `handshake_consume_response` | Initiator: validate message 2. |
| `begin_session` | Derive the directional session keys, reset counters, stamp the keypair birthdate. |

### 1.2a Message framing header — `handshake.c`

Every handshake message begins with a fixed 8-byte `struct noise_message_header`
(`magic`, `type`, `version`, `reserved`), inspired by WireGuard's
`struct message_header` / `enum message_type`. The receiver reads the header
first and `switch`es on its type to route the message. The `magic` ("NOIS")
distinguishes a Noise initiation from a plaintext RPC record marker / TLS on the
shared TCP port (WireGuard owns its UDP socket and so needs no magic). The
header is **framing only**, it means it's not mixed into the Noise transcript, so the
handshake crypto is unchanged.

| Function | Description |
|----------|-------------|
| `noise_message_header_set` | Stamp an outgoing header with the magic/version and a message type. |
| `noise_message_classify` | Validate magic/version/reserved and return the message type (or `NOISE_MSG_INVALID`); the dispatch key, analogous to WireGuard's `SKB_TYPE_LE32()`. |

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

### 1.6 Key management — `noise_keys.c`

A kernel-held keyring `.noise` holds the long-term secrets as `user` keys,
provisioned from userspace with `keyctl(1)`; the handshake looks them up by
description. This replaces the previous hardcoded test keys on both sides. The
PSK is keyed by the **client** static public key (lowercase hex, no separator),
exactly like WireGuard keys a peer's preshared key by its public key.

| Key description | Holds |
|-----------------|-------|
| `noise:priv:server` | server static private scalar (32 B) |
| `noise:priv:client` | client static private scalar (32 B) |
| `noise:pub:server` | server static public key (32 B) |
| `noise:psk:<client-pub-hex>` | pre-shared key for that client (32 B) |

| Function | Description |
|----------|-------------|
| `ikpsk2_keyring_init` / `ikpsk2_keyring_exit` | Allocate / release the `.noise` keyring at module load/unload; exposes its serial via the read-only `keyring_serial` module parameter. |
| `noise_key_lookup` | Copy exactly N bytes of a `user` key payload by description (`0` / `-ENOKEY` / `-EINVAL`). |
| `noise_psk_lookup` | Fetch the PSK keyed by a static public key (`noise:psk:<hex>`); used by the responder after msg1 and by the initiator under its own public key. |

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
| `xs_noise_handshake_sync` | Drive the IKpsk2 initiator exchange (msg1 out, msg2 in), then derive keys. Reads the msg2 framing header first and `switch`es on it: `RESPONSE` → consume; `ERROR` → refused (`-EACCES`); otherwise not Noise (`-EPROTO`). |
| `xs_noise_setup_keys` | Load the client static private key, the server static public key and the PSK from the `.noise` keyring (§1.6) into the peer. |
| `xs_noise_send` | Send exactly N bytes (a handshake message) over the lower socket. |
| `xs_noise_recv` | Block until exactly N bytes (a handshake message) are received. |

### 2.3 Transport phase

Transport-phase encryption is now done by the socket ULP (§1.5), not at the RPC
layer. After the handshake the install call replaces the old per-record hooks,
so the RPC send/receive paths are back to their stock plaintext form and the
socket seals/opens transparently. The previous payload-model helpers
(`xs_noise_send_record`, `xs_noise_recvmsg`, `xs_noise_rx_fill`,
`xs_noise_linearize`, `xs_noise_send_all`, `xs_noise_read_some`, and the
backchannel sealer `xs_noise_bc_send`) have been **removed**; the NFSv4.1
backchannel shares the fore-channel socket and is encrypted by the same ULP.

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
| `svc_noise_handshake` | Run the IKpsk2 responder (msg1 in, msg2 out), then derive keys. Reads the msg1 framing header first and `switch`es on it: `INITIATION` → read the body and consume; otherwise refuse the connection (`-EPROTO`). Reading the 8-byte header before the body lets a non-Noise connection (plaintext RPC / TLS) be rejected before any crypto. |
| `svc_noise_setup_keys` | Load the server static private key from the `.noise` keyring (§1.6); the per-client PSK is selected later, after msg1 reveals the client static key. |
| `svc_noise_send` | Send exactly N bytes (a handshake message) over the socket. |
| `svc_noise_recv` | Block until exactly N bytes (a handshake message) are received. |
| `svc_noise_send_error` | Best-effort header-only `NOISE_MSG_HANDSHAKE_ERROR` reply so a genuine Noise client can tell a refusal apart from a dropped connection. |

### 3.3 Transport phase

As on the client, transport-phase encryption is now done by the socket ULP
(§1.5). The previous payload-model helpers (`svc_noise_recvmsg`,
`svc_noise_rx_fill`, `svc_noise_read_some`, `svc_noise_sendmsg`,
`svc_noise_linearize`, `svc_noise_send_all`) have been **removed**, and
`svc_tcp_sock_recvmsg` / `svc_tcp_sendmsg` are back to their stock plaintext
form over the now-encrypting socket.

---

## 4. Configuration / selection (not functions)

| Item | Side | Description |
|------|------|-------------|
| `xprtsec=noise` mount option | client | Parsed in `fs/nfs/fs_context.c`; selects the Noise transport. |
| `svc_noise` module parameter | server | `net/sunrpc/svcsock.c`; enables the Noise responder on accepted connections. |
| `RPC_XPRTSEC_NOISE` / `XPRT_TRANSPORT_TCP_NOISE` | both | New policy / transport identifiers wiring the option to the transport class. |
