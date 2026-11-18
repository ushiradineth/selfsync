# Security

This is the security maintenance fork at https://github.com/ushiradineth/selfsync.
Report vulnerabilities privately through GitHub Security Advisories. Do not post
credentials, pairing links, vault contents or recovery phrases in public issues.

## Threat model

Run the server on infrastructure you control, behind HTTPS. The server itself
serves HTTP; expose it only to the reverse proxy. Enable SELFSYNC_TRUSTED_PROXY
only when direct access to the server is blocked and the proxy appends a trusted
client address. Without encryption, the server stores plaintext notes.

Every device has a random 256-bit bearer token. The server stores its SHA-256
hash. One-time connection codes contain 80 random bits, expire after 15 minutes
and are stored as hashes. Failed authentication and pairing attempts are rate
limited. Revoking a token stops future API access. Read-only devices cannot
modify vault data or create new pairing codes.

## End-to-end encryption

A random 256-bit master key is wrapped using a password-derived key (Argon2id,
64 MiB, three passes by default). HKDF-SHA256 derives separate keys for content,
nonces, filenames and content identifiers. File contents use AES-256-GCM-SIV in
1 MiB chunks; filenames use AES-SIV. Chunk authentication covers the blob header,
content identifier, chunk index and final-chunk marker. A recovery phrase is
24 BIP-39 words generated from 256 random bits and must be stored privately.

The server still sees file counts, directory depth, approximate filename lengths,
file sizes, modification and sync times, device names, history counts and equality
of contents. Encryption is deterministic to support deduplication and retries.

**This protocol does not authenticate file placement or freshness against a
malicious server.** A compromised server can replay an old valid revision, swap
valid ciphertext between files, hide entries or delete them. Encryption prevents
creating arbitrary new authenticated ciphertext, but does not detect those
whole-record attacks. Independent versioned backups remain necessary. This fork
preserves the upstream protocol and existing vault format; the fixes in 0.10.2 do
not claim to solve this limitation. Solving it requires an authenticated metadata
protocol and a coordinated migration of every client.

Changing the password only rewraps the same master key. Someone who retained an
old key record and its password or recovery phrase retains that master key. After
revoking a compromised device or exposing a password or phrase, rotate the master
key (rekey), not just the password. Rotation cannot revoke files already copied
or older backups encrypted with the old key. Completed rotation removes old-key
server history and trash. Keep and verify an independent backup first.

## Local files and keys

Vault files and the merge-base cache are plaintext on devices. If remember-key is
enabled, the plugin stores the master key in Obsidian local storage, and the CLI
stores it in .selfsync/key with mode 0600. The plugin's device token is in
.obsidian/plugins/selfsync/data.json; the CLI token is in .selfsync/config.toml.
Selfsync excludes its own storage from sync. Other backup or sync tools may still
copy those credentials. Local device compromise is outside the encryption boundary.

Desktop and CLI temporary replacement writes reject existing symbolic and hard
links and create new files exclusively, with private permissions. Desktop parent
directories are rechecked on each operation. This protects against planted link
entries; it is not an operating-system sandbox against a malicious process
concurrently replacing directory trees. Do not share write access to vault or
state directories with untrusted local users or processes. On mobile, filesystem
access is mediated by Obsidian's adapter, which may follow platform links.

## Operations and releases

Use an unprivileged server process, a private data directory and a hardened
container or systemd unit. Regularly run selfsync verify and take consistent
backups with selfsync backup --copy. Test restores; same-disk backups do not
survive disk failure. History and trash are not substitutes for independent backups.

Fork releases are built in GitHub Actions with locked dependencies. Server and
CLI binaries include SHA256SUMS; binary, plugin and GHCR releases carry GitHub
provenance attestations. Verify with gh attestation verify against
ushiradineth/selfsync, and pin the container digest. Checksums alone do not
establish the identity of the publisher. No binary reproducibility verification
is implied by the presence of provenance.

The November 2026 dependency review updated affected Rust TLS, certificate, Tokio,
SQLite and rustix versions. The npm build toolchain uses patched minimatch and fast-uri while retaining
Obsidian lint checks. GitHub withdrew GHSA-fc5q-39xc-vjpf (picomatch) on
2026-11-18, although npm audit still reports its development-tool dependency
chain. Lint glob patterns are trusted repository configuration and never process
untrusted vault input at runtime. See https://github.com/advisories/GHSA-fc5q-39xc-vjpf.
Do not accept untrusted glob patterns in build tooling. humantime remains an
upstream dependency with an informational unmaintained advisory; it is not a
reported exploitable vulnerability. Recheck current advisories before upgrading.
