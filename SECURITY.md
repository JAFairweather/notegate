# Security — what Notegate protects, and what it honestly cannot

Notegate is a pure client. There is no Notegate server: all cryptography
runs in the browser, and the only things that ever leave it are ciphertext
and routing envelopes. This document is the threat model, starting with the
build specification's §2 **verbatim** — read the "NOT protected" half as
carefully as the first half. Tools that overclaim get sources hurt.

## The threat model (spec §2, verbatim)

| **Actor** | **Holds** | **Wants** |
| :-: | :-: | :-: |
| **Recipient** (newsroom, ombudsman, compliance office) | Long-lived *intake keypair*; the app's Grant Index | Receive tips; conduct follow-up dialogue; keep source map unsubpoenable |
| **Source** | *Ephemeral keypair* generated in-browser per submission thread | Submit content + attachments; optionally receive replies; deniability |
| **Relay / blob host** (untrusted) | Ciphertext only | — |
| **Adversary** | Relay logs, network observation, seized recipient device | Identify sources; link sources to stories |

**Protected:** content, attachments, source↔recipient correspondence graph,
case state. Gift wrap hides sender identity from relays; unsigned rumors
make seized messages deniable (no source signature).

**Explicitly NOT protected (state this in the UI, verbatim honesty is a
product requirement):**

- Network metadata. Relays see the submitter's IP. The submission page MUST
  display a plain-language warning and a Tor Browser recommendation before
  first submission.
- Timing correlation across relays. Mitigated (not eliminated) by
  randomized publish delays — see §6.
- A source who loses their ephemeral nsec loses the reply channel
  permanently. This is by design; say so.

## How the protections are implemented

**Tip content and dialogue.** Tips and source replies are unsigned kind-14
rumors, NIP-59 sealed and gift-wrapped to the intake key; recipient replies
live in a per-source NIP-DA case scope (kind 30440, opaque `d` tag,
encrypted under a random scope key granted only to that source's ephemeral
key). Relays see ciphertext from throwaway keys with timestamps fuzzed up
to ±48 h.

**The source map.** The Grant Index (kind 10440) *is* the case docket, and
it is NIP-44-encrypted to the intake key itself. There is no case database
anywhere — nothing to raid, nothing to subpoena beyond the recipient's own
key. Our suites assert this from the adversary's side: after every flow, an
observer-view check confirms a hostile relay learned no source pubkey, no
content, and no case linkage.

**Attachments.** Files are padded to power-of-two size classes, encrypted
under a random per-file key (XChaCha20-Poly1305), and uploaded to Blossom
hosts as unnamed ciphertext. The manifest — name, mime, hash, key — rides
only inside encrypted rumors and case payloads. Hosts learn a size class
and an IP; never a name, a hash of the plaintext, or a byte of content.

**Spam without identity.** The gate is NIP-13 proof of work on the outer
wrap (default 20 bits), judged *before* any decryption — no accounts, no
email, no phone number, nothing that names a source.

**Timing correlation.** Every source-side publish staggers each relay's
copy by an independent random delay of up to 90 seconds. This blurs the
multi-relay arrival signature; it does not defeat a global observer, and
the UI says so while it happens.

**The intake key at rest.** Nothing is persisted unless the recipient opts
in; the "protect this key" offer stores a NIP-49 ncryptsec (the key
encrypted with a passphrase, scrypt) as the only persisted secret. Key
rotation retires the old intake key into the new key's encrypted Grant
Index for a sunset window (default 30 days) — during it, both keys decrypt
and the docket views merge; when it ends, the old key material is deleted
and the old share URL goes dark permanently.

**No hidden egress.** `npm run egress` asserts that shipped code contains
no network destination beyond the configured relays, the two default
Blossom hosts, and esm.sh (pinned modules) — and that the submit page
persists nothing at all. What that test does and does not cover is
documented in its header.

## What is NOT protected — the longer, honest version

**Your IP address.** Relays and blob hosts see the network address of
whoever connects. Notegate is not a metadata-anonymity system: Notegate
*plus Tor Browser* approaches SecureDrop's properties; Notegate alone does
not, and must not claim to. If your situation is serious: Tor Browser,
never a work or home network. (The Tor guidance copy has not had legal or
operational-security review — **review it before real newsroom use.**)

**Timing, globally observed.** The 0–90 s jitter blurs per-relay arrival
correlation; an adversary who watches both your network and the relays can
still correlate sessions. Mitigated, not eliminated.

**A lost recovery phrase.** The 12 words shown after sending are the only
reply channel; there is no reset, no account, no server copy. Losing them
closes the conversation permanently — by design, because anything that
could recover the channel could also impersonate the source.

**A seized or compromised recipient device.** An unlocked inbox decrypts
everything the intake key can decrypt. The at-rest artifact is the
passphrase-encrypted ncryptsec, only as strong as the passphrase; the
archive triage list stores ephemeral thread pubkeys (not identities, not
keys) in localStorage. JavaScript cannot reliably zero memory — key bytes
are wiped where feasible (`fill(0)`), but a hostile OS-level snapshot of a
running session sees keys.

**A compromised source device.** Same physics: malware on the source's
machine reads the tip before encryption and the phrase as it is shown.

**Deniability is not anonymity.** Unsigned rumors mean a seized transcript
carries no cryptographic proof of who wrote it. That helps a source deny
authorship; it does not stop an adversary who already linked traffic to a
person by other means.

**Relays may keep everything.** Deletion and replacement are requests
honored by honest relays. Assume every ciphertext ever published is
retained somewhere forever, and judge the encryption accordingly.

**The code delivery path.** The pages load pinned modules from esm.sh with
no build step. You trust that CDN and whoever serves you the page. For a
real deployment, serve the repo yourself and read `test/egress.mjs`.

**Draft protocol.** Built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411)); kind
numbers are placeholders and may change. Use throwaway keys until it
settles.

## Reporting

Found a hole? Open an issue at
<https://github.com/JAFairweather/notegate/issues> — or, for anything
sensitive, contact the maintainer privately first.
