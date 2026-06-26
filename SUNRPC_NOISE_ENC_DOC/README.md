# NFSv4 (SUNRPC) data-in-transit encryption over NOISE IKpsk2

<p align="justify">This Linux kernel fork implements data-in-flight encryption for NFSv4 using the Noise IKpsk2 cryptographic protocol framework.

Designed as a modern alternative to traditional NFSv4 encryption methods, this implementation operates directly at the RPC layer (Session Layer / Layer 5 of the OSI model).</p>

<p align="justify">Unlike this Noise-based implementation, native RPC/NFS encryption options currently rely on one of two approaches:</p>

- RPC-with-TLS: Encrypts the entire underlying TCP socket using Transport Layer Security (via Kernel TLS/ULP), passing standard RPC records through the encrypted transport.
- RPC SEC_GSS (Kerberos): Operates at the RPC layer but relies on a Kerberos infrastructure, encrypting only the RPC message bodies (payloads) while leaving the headers intact.

<p align="justify">This implementation draws inspiration from Wireguard's state machine and cryptography.</p>

> This implementation is a prototype and is designed only for the purpose of testing. Current issues and security concerns are considered in a dedicated section below.

## Key concepts

### Noise package

<p align="justify">The Noise protocol support is implemented as a self-contained in-kernel subsystem, placed under the networking tree alongside the existing transport-security code (the same location as the kernel TLS support). It is integrated into the standard kernel build and configuration system, so it can be enabled or disabled through a dedicated configuration option and built either into the kernel or as a separate component, in the same way as the other networking features.</p>

<p align="justify">The package is organised around a clear separation of responsibilities: an entry/initialisation part, the handshake logic implementing the Noise IKpsk2 exchange, the transport part responsible for sealing and opening records once the session is established, and the underlying cryptographic helpers. The handshake implementation is kept in its own namespace, which leaves room for additional Noise patterns to be added later without disturbing the rest of the structure.</p>

<p align="justify">Crucially, this subsystem is not a user-facing service or a separate on-wire protocol of its own. It exposes a small in-kernel programming interface, declared in a single public header, that other kernel subsystems can call to perform the handshake and to encrypt or decrypt data. In this work that consumer is SUNRPC, but the interface is deliberately generic, so the same building block could be reused by other in-kernel components that need an authenticated, encrypted channel. This mirrors the design philosophy of the kernel TLS code, which similarly provides encryption services to upper layers rather than being tied to a single application.</p>

### NFSv4/RPC payload encryption

<p align="justify">NFSv4 traffic is encapsulated by RPC, so the encryption is applied at this level. It relies on the following primitives:</p>

- Key pair: Curve25519 / X25519 + ECDH (kernel)
- Hash function: blake2s (kernel)
- Handshake and transport encryption/decryption (AEAD): chacha20poly1305 (kernel)
- Key derivation (symmetric keys): HKDF

<p align="justify">The exchange follows the Noise IKpsk2 pattern: a short handshake authenticates both ends and establishes a pair of directional symmetric keys, after which every RPC record is sealed with authenticated encryption. The same AEAD primitive is used throughout and during the handshake to protect the exchanged fields, and during the transport phase to protect the payload; the difference being that the transport phase uses long-lived session keys together with a monotonically increasing counter that serves both as the encryption nonce and as an in-order anti-replay value.</p>

<p align="justify">Compared to RPC-with-TLS, which encrypts the TCP socket itself after a TLS handshake (ULP), this implementation encrypts the RPC records rather than the channel. In other words, encrypted RPC records are written onto an otherwise unencrypted socket, which is the converse of TLS, where cleartext records are written onto an encrypted socket. Compared to Kerberos, which seals only the message body, this approach seals the complete record.</p>

### NFSv4 metadata encryption

<p align="justify">Because encryption is applied to the whole RPC record and not only to the procedure arguments, the RPC and program metadata, the transaction identifiers, program and procedure information, operation structure and message sizes, are concealed as well. This is a notable difference from the Kerberos privacy service, which leaves the RPC headers in clear and therefore exposes this metadata to an on-path observer. Sealing the entire record removes that traffic-analysis surface, at the cost of being a channel-oriented rather than identity-oriented protection.</p>

### NFSv4 callback channel encryption

<p align="justify">NFSv4 uses a server-to-client callback channel (for example for delegations and recalls). Because this design is a tunnel-style scheme, the receiver treats every incoming byte as part of a sealed record and uses a single per-connection framing state to rebuild records before decrypting. If unencrypted callback traffic were allowed to reach that pipeline, its leading bytes would be misinterpreted as a record length, the framing would lose alignment with the real byte stream, and the reassembly state would desynchronise instead of resetting; leading to oversized or malformed records and errors. For this reason the return/callback direction must also be encrypted, so that the pipeline only ever sees sealed records. This is a structural consequence of channel encryption: a per-message scheme such as Kerberos is direction-agnostic and does not suffer from it, since an unwrapped message simply cannot corrupt its neighbours.</p>

### XDR buffer linearization

<p align="justify">An RPC message is represented as a scatter-gather structure: a header region, a list of payload pages that may reside in high memory, and a trailing region. These parts are not contiguous in memory. Authenticated encryption, however, needs a single contiguous input covered by one authentication tag. The message fragments are therefore gathered into one flat buffer before sealing, and split back out after opening. The trade-off is the loss of the usual zero-copy send path: each message incurs an additional copy of its payload. Performing scatter-gather encryption directly over the message fragments would remove this copy and is a natural avenue for improvement.</p>

### TCP reassembly

<p align="justify">WireGuard operates over UDP, where one datagram corresponds to exactly one record, so no reassembly is required. RPC operates over TCP, which is a continuous byte stream: a single sealed record may be split across several reads, or several records may arrive together. The receiver therefore maintains per-connection reassembly state to reconstruct complete records (first the length prefix, then the body) before any decryption is attempted. This reassembly logic is specific to running the scheme over a stream transport and has no equivalent in the original datagram-based design.</p>

### Client/Server model

<p align="justify">The selection mechanism mirrors the way existing NFS security modes are chosen. On the client, the encryption is requested through the standard transport-security mount option (xprtsec=noise), which routes the connection to a dedicated Noise transport that runs the handshake as part of establishing the connection. On the server, the feature is enabled through a kernel module parameter (svc_noise), after which accepted connections run the Noise responder before serving any traffic. Each connection keeps its own independent cryptographic state, so multiple clients are handled separately and concurrently, exactly as with classical NFS, RPC-with-TLS, or Kerberos.</p>

## Areas of improvement

### Security concerns

<p align="justify">The current prototype carries a number of known limitations that would need to be addressed before any real use:</p>

- The static keys and pre-shared key are hardcoded and should be moved to proper configuration (for example a keyring or per-export options) rather than being fixed in the source.
- The handshake is exposed to denial-of-service: an attacker can open connections and trigger or stall handshakes. Because the responder handshake is synchronous, this can tie up server worker threads, and there is presently no rate limiting on handshake attempts.
- Client identity is authenticated but not yet authorized: any peer completing the handshake is accepted, as there is no check of the remote static key against an allow-list.

### Missing implementations or features

<p align="justify">Several mechanisms present in the original WireGuard design are not implemented, and their relevance here depends on the fact that the scheme runs over a managed TCP/RPC transport rather than over UDP:</p>

- Rekeying: there is currently no periodic refresh of the session keys for long-lived, continuously busy connections. Forward secrecy is already obtained at each new connection, so a simple option is to force a reconnection once a time or volume threshold is reached, reusing the existing reconnect path rather than rekeying in place.
- Behaviour for clients that mount without the option: the server currently expects the handshake on every accepted connection when enabled. A cleaner alternative would be an explicit negotiation/probe (as RPC-with-TLS does), allowing encrypted and unencrypted clients to coexist and giving a clear signal when encryption is required.
- Anti-DoS cookie mechanism: WireGuard mitigates handshake flooding with a cookie/return-routability step and rate limiting. Over TCP, return-routability is already provided by the transport handshake, so the most useful additions are a non-blocking handshake and a simple per-source rate limit rather than the full cookie machinery.

### Extensibility to other Noise patterns

<p align="justify">The package currently implements a single Noise pattern (IKpsk2), and much of its naming and structure is tied to that choice: the symbols and functions are specific to this handshake rather than expressed in terms of a generic Noise interface. To support additional patterns in the future (for instance ones with different authentication or anonymity properties), the package would benefit from being reshaped around a pattern-agnostic interface. This means generalising the function names and the public API so that the pattern-independent steps (the chaining-key and transcript operations, the Diffie-Hellman mixing, the record sealing and opening) are separated from the pattern-specific message sequence, and letting each concrete pattern plug into that common framework. Such a refactor would turn the current single-pattern prototype into a small Noise framework where IKpsk2 is just one of several selectable handshakes, without affecting the transport phase or the consuming subsystems.</p>
