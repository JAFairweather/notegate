# Notegate

**Serverless secure tip intake — no server ever holds plaintext.** A tip line
is a nostr keypair. Sources need no account, no app, and no identity: the
submit page mints an ephemeral key in the browser, encrypts the tip to the
newsroom's intake key (NIP-59 gift wrap), pays a NIP-13 proof-of-work toll as
the spam gate, and publishes to public relays with randomized delays. The
inbox polls those relays, rejects underpaid wraps *before* decrypting
anything, and threads tips by ephemeral source key. A 12-word recovery
phrase is the source's only reply channel — lose it and the conversation is
gone, by design.

Relays see ciphertext addressed to the intake key, from throwaway keys, with
fuzzed timestamps and per-relay randomized publish delays (0–90 s). They
never see who sent a tip, what it says, or that a newsroom read it. Built on
draft NIP-DA
([Scoped Data Grants](https://github.com/JAFairweather/nostr-scoped-data-grants)):
follow-up dialogue uses per-source scoped data sets, and the Grant Index
*is* the case docket — the whole thing reconstitutes from the intake nsec
alone, on any device.

What's here (v1 feature-complete, M1–M4):

- **Tip line** — submit page (PoW spam gate, gift wrap, honest metadata/Tor
  warning) + inbox (PoW gate *before* decryption, threading, triage).
- **Dialogue** — replying opens an encrypted per-source case; the source
  returns with their 12-word phrase and nothing else.
- **Attachments** — both directions: padded to size classes, encrypted
  on-device, mirrored to Blossom hosts as unnamed ciphertext. 100 MB cap.
- **Hardening** — 0–90 s per-relay publish jitter; intake key rotation with
  a sunset window (old key keeps decrypting, merged docket with per-key
  badges, key material deleted at expiry); NIP-49 ncryptsec as the sole
  at-rest secret; a zero-egress enforcement test; [SECURITY.md](SECURITY.md)
  with the threat model verbatim, including what is **not** protected.

Status: **alpha** — built on draft NIP-DA
([review pending](https://github.com/nostr-protocol/nips/pull/2411));
kind numbers may change. **Not yet reviewed for real newsroom use** — read
[SECURITY.md](SECURITY.md) and the metadata warning on the submit page;
IP-level anonymity is Tor's job, not this app's.

```
npm install
npm run smoke:local     # in-memory relay; npm run smoke = live relays, real 20-bit PoW
npm run e2e             # full source→tip→inbox loop + publish-jitter contract, in-memory
npm run dialogue:local  # case scopes, docket, returning source (npm run dialogue = live)
npm run attach          # encrypted attachments, mock Blossom (attach:live = real servers)
npm run rotate:local    # key rotation + sunset window (npm run rotate = live)
npm run egress          # zero-egress: origin scan, import traps, at-rest discipline
npm run web             # http://localhost:4442/  (inbox; share URL points at /submit/)
```

Pure client: no server, no accounts, no build step. `lib/` is vendored from
the protocol repo (`npm run sync-lib`). MIT.
