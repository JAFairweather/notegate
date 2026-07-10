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
fuzzed timestamps. They never see who sent a tip, what it says, or that a
newsroom read it. Built on draft NIP-DA
([Scoped Data Grants](https://github.com/JAFairweather/nostr-scoped-data-grants)):
follow-up dialogue (M2) uses per-source scoped data sets, and the Grant Index
becomes the case docket.

Status: **alpha** — M1 (one-way tip line: submit page + inbox with PoW gate,
threading, archive triage). Dialogue, attachments, and hardening are next.
Built on draft NIP-DA ([review pending](https://github.com/nostr-protocol/nips/pull/2411));
kind numbers may change. **Not yet reviewed for real newsroom use** — read
the metadata warning on the submit page; IP-level anonymity is Tor's job,
not this app's.

```
npm install
npm run smoke:local   # in-memory relay, 10 assertions incl. adversarial observer view
npm run smoke         # same against live public relays (real 20-bit PoW)
npm run e2e           # full source→tip→inbox loop, in-memory
npm run web           # http://localhost:4442/  (inbox; share URL points at /submit/)
```

Pure client: no server, no accounts, no build step. `lib/` is vendored from
the protocol repo (`npm run sync-lib`). MIT.
