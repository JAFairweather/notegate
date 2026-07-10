// smoke.mjs — Notegate M1: anonymous tip → PoW gate → inbox.
//
//   node test/smoke.mjs --local     # in-memory relay, low PoW (8 bits)
//   node test/smoke.mjs             # live relays, real PoW (20 bits)

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { Relay } from '../lib/relay.mjs'
import { LiveRelay, LocalRelay } from '../lib/liverelay.mjs'
import { wrapWithPow, unwrap, powBits } from '../shared/wrap.mjs'

const local = process.argv.includes('--local')
const inner = local ? new Relay() : null
const relay = local ? new LocalRelay(inner)
  : new LiveRelay(['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net'])
const BITS = local ? 8 : 20
console.log(local ? 'mode: LOCAL (8-bit PoW)' : 'mode: LIVE (20-bit PoW)')
const settle = () => local ? Promise.resolve() : new Promise(r => setTimeout(r, 1500))

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

const intake = generateSecretKey()          // the newsroom
const intakePub = getPublicKey(intake)
const source = generateSecretKey()          // ephemeral, per-thread

try {
  console.log('\n1. Source submits a tip (PoW-mined gift wrap, unsigned rumor)')
  const rumor = {
    kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
    content: JSON.stringify({ text: 'the mayor eats the good biscuits', thread: null }),
  }
  const t0 = Date.now()
  const wrap = await wrapWithPow(source, intakePub, rumor, BITS)
  check(`wrap carries ≥${BITS} bits of PoW`, powBits(wrap) >= BITS, `${powBits(wrap)} bits in ${Date.now() - t0}ms`)
  check('rumor is unsigned (deniable)', !('sig' in rumor))
  const p = await relay.publish(wrap)
  check('relay accepts the wrap', (p.acks ?? 1) > 0)
  await settle()

  console.log('\n2. Inbox: PoW gate before decryption, then unwrap')
  const wraps = await relay.query({ kinds: [1059], '#p': [intakePub] })
  const passing = wraps.filter(w => powBits(w) >= BITS)
  check('wrap found addressed to intake key', passing.length >= 1)
  const tip = unwrap(intake, passing[0])
  check('tip decrypts and reads', JSON.parse(tip.content).text.includes('biscuits'))
  check('thread id = ephemeral source pubkey', tip.pubkey === getPublicKey(source))

  console.log('\n3. Spam gate: sub-threshold wrap is rejected without decryption')
  const lazy = await wrapWithPow(generateSecretKey(), intakePub, { ...rumor, id: undefined }, 0)
  check('0-bit wrap fails the gate', powBits(lazy) < BITS)

  if (local) {
    console.log('\n4. Adversarial observer view')
    const view = inner.observerView()
    const blob = JSON.stringify(view)
    check('no tip content visible', !blob.includes('biscuits') && !blob.includes('mayor'))
    check('no source pubkey visible', !blob.includes(getPublicKey(source)))
    check('wrap sender is ephemeral, not the source',
      inner.events[0].pubkey !== getPublicKey(source) && inner.events[0].pubkey !== intakePub)
  }

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close?.()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mSmoke aborted:\x1b[0m', err.message)
  relay.close?.()
  process.exit(1)
}
