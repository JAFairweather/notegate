// dialogue.mjs — Notegate M2: the full dialogue loop.
//
//   node test/dialogue.mjs --local     # in-memory relay, low PoW (8 bits)
//   node test/dialogue.mjs             # live relays, real PoW (20 bits)
//
// source → tip → recipient reply (case scope + grant + docket) → source
// reconstitutes from the BIP-39 words alone and reads the case → source
// replies at the recipient's PoW price → recipient sees it and syncs the
// case → the docket reconstitutes from the intake nsec alone on a fresh
// device. Adversarial observer assertions after the whole flow (local mode).

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { generateSeedWords, privateKeyFromSeedWords } from 'nostr-tools/nip06'
import { Relay } from '../lib/relay.mjs'
import { LiveRelay, LocalRelay } from '../lib/liverelay.mjs'
import { wrapWithPow, unwrap, powBits } from '../shared/wrap.mjs'
import { receiveGrants, latestGrants, fetchScope, loadGrantIndex, fromIssuedEntry } from '../lib/nipxx.mjs'
import { loadDocket, upsertCase, fetchCase, caseOutOfSync } from '../inbox/case.mjs'

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
const tipRumor = (text, thread = null) => ({
  kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
  content: JSON.stringify({ notegate: 1, text, thread }),
})
// the inbox pipeline, verbatim: poll → PoW gate BEFORE unwrap → thread by rumor pubkey
async function inboxThreads(intakeSk) {
  const wraps = await relay.query({ kinds: [1059], '#p': [getPublicKey(intakeSk)], limit: 500 })
  const threads = new Map()
  for (const wrap of wraps) {
    if (powBits(wrap) < BITS) continue
    let rumor; try { rumor = unwrap(intakeSk, wrap) } catch { continue }
    if (rumor.kind !== 14) continue                     // grants to sources are not tips
    const { text } = JSON.parse(rumor.content)
    const msgs = threads.get(rumor.pubkey) ?? []
    msgs.push({ at: rumor.created_at, text })
    msgs.sort((a, b) => a.at - b.at)
    threads.set(rumor.pubkey, msgs)
  }
  return threads
}

const intake = generateSecretKey()
const intakePub = getPublicKey(intake)

try {
  console.log('\n1. Source tips; the words ARE the reply channel')
  const words = generateSeedWords()
  const srcSk = privateKeyFromSeedWords(words)          // Uint8Array in nostr-tools 2.x
  const srcPub = getPublicKey(srcSk)
  await relay.publish(await wrapWithPow(srcSk, intakePub, tipRumor('the ledgers in slip 14 are forged'), BITS))
  await settle()
  let threads = await inboxThreads(intake)
  check('tip lands in the inbox thread', threads.get(srcPub)?.[0].text.includes('slip 14'))

  console.log('\n2. First reply mints the case: scope + grant + docket entry')
  const docket = await loadDocket(relay, intake)
  check('docket starts empty', docket.cases.size === 0)
  const { case: c, payload, isNew } = await upsertCase(relay, intake, docket, srcPub, {
    sourceMsgs: threads.get(srcPub), replyText: 'which registry office stamped them?', powPolicy: BITS,
  })
  await settle()
  check('first reply creates the case', isNew && payload.status === 'open')
  const [scopeEv] = await relay.query({ kinds: [30440], authors: [intakePub], '#d': [c.scopeId] })
  check('case scope is on the relay, generation 1',
    scopeEv && scopeEv.tags.find(t => t[0] === 'v')?.[1] === '1')
  check('case scope d tag is opaque (no thread linkage)',
    /^[0-9a-f]{32}$/.test(c.scopeId) && !c.scopeId.includes(srcPub.slice(0, 8)))
  const idx = await loadGrantIndex(relay, intake)
  check('docket records the case, grantee = ephemeral source key',
    idx.issued.length === 1 && idx.issued[0].grantees[0] === srcPub && idx.issued[0].status === 'open')

  console.log('\n3. Returning source: BIP-39 words alone reopen the dialogue')
  const retSk = privateKeyFromSeedWords(words)          // fresh derivation, nothing else kept
  const grants = latestGrants(await receiveGrants(relay, retSk))
  const g = grants.find(g => g.publisher === intakePub)
  check('grant reaches the ephemeral key', Boolean(g))
  const view = await fetchScope(relay, g)
  check('source dereferences the case', view.status === 'ok')
  check('case carries the merged dialogue', view.data.messages.length === 2 &&
    view.data.messages[0].from === 'source' && view.data.messages[1].from === 'recipient')
  check('recipient PoW policy rides in the payload', view.data.pow === BITS)

  console.log('\n4. Source replies at that price; recipient syncs the case')
  await relay.publish(await wrapWithPow(retSk, intakePub,
    tipRumor('the harbourmaster’s office, third window', srcPub), view.data.pow))
  await settle()
  threads = await inboxThreads(intake)
  check('reply threads with the original tip (same ephemeral pubkey)',
    threads.get(srcPub)?.length === 2)
  check('caseOutOfSync flags the new source message',
    caseOutOfSync((await fetchCase(relay, intakePub, c)).data, threads.get(srcPub)))
  await upsertCase(relay, intake, docket, srcPub, { sourceMsgs: threads.get(srcPub), powPolicy: BITS })
  await settle()
  const resync = await fetchScope(relay, g)
  check('update is free: same key, same generation, three messages',
    resync.status === 'ok' && resync.generation === 1 && resync.data.messages.length === 3)

  console.log('\n5. Fresh device: docket reconstitutes from the intake nsec alone')
  const recovered = await loadGrantIndex(relay, intake)   // nothing in memory but the key
  const rc = { ...fromIssuedEntry(recovered.issued[0]), status: recovered.issued[0].status }
  const reread = await fetchCase(relay, intakePub, rc)
  check('recovered docket dereferences the full dialogue',
    reread.status === 'ok' && reread.data.messages.length === 3)
  check('payload and docket agree on status',
    reread.data.status === 'open' && rc.status === 'open')

  console.log('\n6. Archive: status lives in the payload AND the docket')
  await upsertCase(relay, intake, docket, srcPub,
    { sourceMsgs: threads.get(srcPub), status: 'archived', powPolicy: BITS })
  await settle()
  const archIdx = await loadGrantIndex(relay, intake)
  const archView = await fetchScope(relay, g)
  check('both sides see archived',
    archIdx.issued[0].status === 'archived' && archView.data.status === 'archived')

  if (local) {
    console.log('\n7. Adversarial observer view (what relays see)')
    const blob = JSON.stringify(inner.observerView())
    check('no dialogue content visible', !blob.includes('slip 14') &&
      !blob.includes('registry') && !blob.includes('harbourmaster'))
    check('source pubkey never appears as an author', !blob.includes(srcPub.slice(0, 8)))
    check('every wrap author is ephemeral (no intake↔source linkage)',
      inner.events.filter(e => e.kind === 1059)
        .every(e => e.pubkey !== intakePub && e.pubkey !== srcPub))
    check('case scope content and docket are ciphertext',
      inner.events.filter(e => e.kind === 30440 || e.kind === 10440)
        .every(e => !e.content.includes('messages') && !e.content.includes('archived')))
  }

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  relay.close?.()
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mDialogue test aborted:\x1b[0m', err)
  relay.close?.()
  process.exit(1)
}
