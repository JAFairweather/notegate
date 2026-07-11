// rotate.mjs — Notegate M4: intake key rotation + sunset window.
//
//   node test/rotate.mjs --local     # in-memory relay, low PoW (8 bits)
//   node test/rotate.mjs             # live relays, real PoW (20 bits)
//
// tip → case under the OLD key → rotate → everything (old key included)
// reconstitutes from the NEW nsec alone → merged view decrypts both keys'
// wraps and cases → rotations chain → sunset expiry deletes the old key
// material from the index. Observer assertions in local mode.

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { Relay } from '../lib/relay.mjs'
import { LiveRelay, LocalRelay } from '../lib/liverelay.mjs'
import { wrapWithPow, unwrap, powBits } from '../shared/wrap.mjs'
import { loadGrantIndex } from '../lib/nipxx.mjs'
import { loadDocket, upsertCase, fetchCase } from '../inbox/case.mjs'
import { rotateIntakeKey, pruneRetired, retiredKeys, skFromHex, DEFAULT_SUNSET_DAYS } from '../inbox/rotate.mjs'

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
const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const tipRumor = (text, thread = null) => ({
  kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
  content: JSON.stringify({ notegate: 1, text, thread }),
})
// the inbox's merged pipeline: one query for every watched key, wrap routed
// to its key by the p tag, PoW gate before unwrap
async function mergedThreads(keys) {
  const wraps = await relay.query({ kinds: [1059], '#p': keys.map(k => k.pk), limit: 500 })
  const threads = new Map()
  for (const wrap of wraps) {
    if (powBits(wrap) < BITS) continue
    const key = keys.find(k => k.pk === wrap.tags.find(t => t[0] === 'p')?.[1])
    if (!key) continue
    let rumor; try { rumor = unwrap(key.sk, wrap) } catch { continue }
    if (rumor.kind !== 14) continue
    const msgs = threads.get(rumor.pubkey) ?? []
    msgs.push({ at: rumor.created_at, text: JSON.parse(rumor.content).text, via: key.pk })
    threads.set(rumor.pubkey, msgs)
  }
  return threads
}

const oldSk = generateSecretKey()
const oldPub = getPublicKey(oldSk)
const now = Math.floor(Date.now() / 1000)

try {
  console.log('\n1. Life before rotation: a tip and a case under the old intake key')
  const src = generateSecretKey()
  const srcPub = getPublicKey(src)
  await relay.publish(await wrapWithPow(src, oldPub, tipRumor('the berth 9 crane logs are doctored'), BITS))
  await settle()
  const docket = await loadDocket(relay, oldSk)
  await upsertCase(relay, oldSk, docket, srcPub, {
    sourceMsgs: [{ at: now, text: 'the berth 9 crane logs are doctored' }],
    replyText: 'doctored how?', powPolicy: BITS,
  })
  await settle()
  check('tip + open case exist under the old key', docket.cases.has(srcPub))

  console.log('\n2. Rotate: fresh key, retired entry in the NEW index, new kind-0')
  const { newSk, index } = await rotateIntakeKey(relay, oldSk, { name: 'Rotated Desk', sunsetDays: DEFAULT_SUNSET_DAYS, now })
  const newPub = getPublicKey(newSk)
  await settle()
  check('sunset default is 30 days', DEFAULT_SUNSET_DAYS === 30)
  check('new index carries the retired key with a sunset deadline',
    index.notegate_retired.length === 1 && index.notegate_retired[0].pk === oldPub
    && index.notegate_retired[0].until === now + 30 * 86400)
  const [k0] = await relay.query({ kinds: [0], authors: [newPub], limit: 1 })
  check('new key has a kind-0 (submit page renders the same tip-line name)',
    JSON.parse(k0?.content ?? '{}').name === 'Rotated Desk')

  console.log('\n3. Fresh device, NEW nsec alone: old key + docket reconstitute')
  const recovered = await loadGrantIndex(relay, newSk)
  const ret = retiredKeys(recovered, now)
  check('retired key recovers from the new nsec alone', ret.length === 1 && ret[0].sk === hexOf(oldSk))
  const recOldSk = skFromHex(ret[0].sk)
  const keys = [{ sk: newSk, pk: newPub }, { sk: recOldSk, pk: ret[0].pk }]
  let threads = await mergedThreads(keys)
  check('old-key tip decrypts in the merged view, badged to the retired key',
    threads.get(srcPub)?.[0].via === oldPub && threads.get(srcPub)[0].text.includes('berth 9'))
  const oldDocket = await loadDocket(relay, recOldSk)
  const c = oldDocket.cases.get(srcPub)
  const dialogue = await fetchCase(relay, oldPub, c)
  check('old-key case dialogue still reads (and updates) during the sunset',
    dialogue.status === 'ok' && dialogue.data.messages.length === 2)

  console.log('\n4. New share URL works: tip to the NEW key lands beside the old thread')
  const src2 = generateSecretKey()
  await relay.publish(await wrapWithPow(src2, newPub, tipRumor('fresh tip to the rotated line'), BITS))
  await settle()
  threads = await mergedThreads(keys)
  check('both threads visible: one per key', threads.size === 2
    && threads.get(getPublicKey(src2))?.[0].via === newPub)

  console.log('\n5. Rotations chain: rotating again carries the still-active old key forward')
  const { newSk: newestSk, index: idx2 } = await rotateIntakeKey(relay, newSk, { name: 'Rotated Desk', now: now + 60 })
  await settle()
  check('index now retires both prior keys',
    idx2.notegate_retired.length === 2
    && idx2.notegate_retired.map(e => e.pk).sort().join() === [oldPub, newPub].sort().join())

  console.log('\n6. Sunset expiry deletes the old key material')
  const kept = await pruneRetired(relay, newestSk, idx2, now + 60 + 31 * 86400)
  await settle()
  const reread = await loadGrantIndex(relay, newestSk)
  check('both keys expired 31 days after the last rotation', kept.length === 0)
  check('the re-read index holds no key material — deletion, not hiding',
    !(JSON.stringify(reread).includes(hexOf(oldSk)) || JSON.stringify(reread).includes(hexOf(newSk))))
  check('expired keys no longer parse as watchable', retiredKeys(reread, now + 60 + 31 * 86400).length === 0)

  if (local) {
    console.log('\n7. Adversarial observer view (what relays see)')
    const blob = JSON.stringify(inner.events)
    check('no secret key ever touches the wire in the clear',
      !blob.includes(hexOf(oldSk)) && !blob.includes(hexOf(newSk)) && !blob.includes(hexOf(newestSk)))
    check('indexes are ciphertext (no "notegate_retired", no "until")',
      inner.events.filter(e => e.kind === 10440)
        .every(e => !e.content.includes('notegate_retired') && !e.content.includes('until')))
    check('no linkage: old and new intake keys never co-sign or co-tag one event',
      inner.events.every(e => {
        const s = JSON.stringify(e)
        return !(s.includes(oldPub) && s.includes(getPublicKey(newSk)))
      }))
  }

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close?.()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mRotation test aborted:\x1b[0m', err)
  relay.close?.()
  process.exit(1)
}
