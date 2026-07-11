// e2e.mjs — full source→tip→inbox loop on the in-memory relay, mirroring
// the exact pipeline inbox.mjs runs: kind-0 identity publish, PoW-mined
// wraps from two independent sources (one sends a follow-up), then the
// inbox side: poll → PoW gate BEFORE unwrap → thread by rumor pubkey.
//
//   node test/e2e.mjs

import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { wrapWithPow, unwrap, powBits } from '../shared/wrap.mjs'
import { publishJittered, MAX_JITTER_MS, currentMaxJitterMs } from '../shared/jitter.mjs'

const BITS = 8                       // low difficulty for tests; the gate logic is identical
const inner = new Relay()
const relay = new LocalRelay(inner)

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}
const tip = (text, thread = null) => ({
  kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
  content: JSON.stringify({ notegate: 1, text, thread }),
})

const intake = generateSecretKey()
const intakePub = getPublicKey(intake)

console.log('\n1. Newsroom setup: publish kind-0, build share URL')
await relay.publish(finalizeEvent({
  kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [],
  content: JSON.stringify({ name: 'Test Desk', about: 'Secure tip line (Notegate)' }),
}, intake))
const [profile] = await relay.query({ kinds: [0], authors: [intakePub], limit: 1 })
check('kind-0 readable by the submit page', JSON.parse(profile.content).name === 'Test Desk')
const npub = nip19.npubEncode(intakePub)
const shareUrl = `https://example.invalid/submit/#${npub}`
check('share URL fragment round-trips to the intake pubkey',
  nip19.decode(shareUrl.split('#')[1]).data === intakePub)

console.log('\n2. Two sources submit tips; source A sends a follow-up')
const srcA = generateSecretKey(), srcB = generateSecretKey()
await relay.publish(await wrapWithPow(srcA, intakePub, tip('dock records do not match the manifest'), BITS))
await relay.publish(await wrapWithPow(srcB, intakePub, tip('second, unrelated source'), BITS))
await relay.publish(await wrapWithPow(srcA, intakePub, tip('follow-up: try berth 9'), BITS))
// and a spammer who refuses to pay for PoW
await relay.publish(await wrapWithPow(generateSecretKey(), intakePub, tip('buy my coin'), 0))

console.log('\n3. Inbox pipeline: poll → PoW gate before unwrap → thread')
const wraps = await relay.query({ kinds: [1059], '#p': [intakePub], limit: 500 })
check('all four wraps arrive', wraps.length === 4)
let gated = 0
const threads = new Map()
for (const wrap of wraps) {
  if (powBits(wrap) < BITS) { gated++; continue }     // never decrypted
  const rumor = unwrap(intake, wrap)
  const { text } = JSON.parse(rumor.content)
  const msgs = threads.get(rumor.pubkey) ?? []
  msgs.push({ at: rumor.created_at, text })
  threads.set(rumor.pubkey, msgs)
}
check('PoW gate rejects exactly the spam wrap without decryption', gated === 1)
check('tips thread into two conversations', threads.size === 2)
const threadA = threads.get(getPublicKey(srcA))
check('source A thread holds both messages', threadA?.length === 2)
check('follow-up shares the thread (same ephemeral pubkey)',
  threadA?.some(m => m.text.includes('berth 9')) && threadA?.some(m => m.text.includes('manifest')))
check('source B thread is separate', threads.get(getPublicKey(srcB))?.length === 1)

console.log('\n4. Adversarial observer view (what relays see)')
const blob = JSON.stringify(inner.observerView())
check('no tip content visible', !blob.includes('manifest') && !blob.includes('berth'))
check('no source pubkey visible',
  !blob.includes(getPublicKey(srcA)) && !blob.includes(getPublicKey(srcB)))
check('intake pubkey appears only as routing tag, never as author',
  inner.events.filter(e => e.kind === 1059).every(e => e.pubkey !== intakePub))

console.log('\n5. Per-relay publish jitter (delays near-zero here; 0–90s in the page)')
check('default window is the spec’s 0–90s', MAX_JITTER_MS === 90_000 && currentMaxJitterMs() === 90_000)
const inners5 = [new Relay(), new Relay(), new Relay()]
const relays5 = inners5.map(r => new LocalRelay(r))
const wrap5 = await wrapWithPow(generateSecretKey(), intakePub, tip('jitter check'), BITS)
const progress = []
const r5 = await publishJittered(relays5, wrap5,
  { maxMs: 120, onProgress: (n, of) => progress.push([n, of]) })
check('every relay eventually receives the wrap (independent delays)',
  r5.acks === 3 && inners5.every(r => r.events.some(e => e.id === wrap5.id)))
check('each relay drew its own delay inside the window',
  r5.delays.length === 3 && r5.delays.every(d => d >= 0 && d < 120))
check('progress narrated per relay', progress.length === 3 && progress[2][0] === 3)
const broken = [{ publish: async () => { throw new Error('rate limited') } }, relays5[0]]
const r5b = await publishJittered(broken, wrap5, { maxMs: 50 })
check('≥1-ack contract: one dead relay does not fail the publish', r5b.acks === 1 && r5b.of === 2)
let allDead = null
try { await publishJittered([broken[0]], wrap5, { maxMs: 50 }) } catch (err) { allDead = err }
check('zero acks is a hard failure', allDead?.message.includes('no relay accepted'))
check('test hook: NOTEGATE_MAX_JITTER_MS overrides the window',
  (globalThis.NOTEGATE_MAX_JITTER_MS = 7, currentMaxJitterMs() === 7,
   delete globalThis.NOTEGATE_MAX_JITTER_MS, currentMaxJitterMs() === 90_000))

console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
process.exit(failed === 0 ? 0 : 1)
