// attach.mjs — Notegate M3: encrypted attachments, both directions.
//
//   node test/attach.mjs            # mock Blossom servers (in-memory, authed)
//   node test/attach.mjs --live     # real public Blossom servers, real files
//
// source attaches a file on the tip (manifest entry INSIDE the encrypted
// rumor) → recipient fetches → hash-verifies → decrypts byte-identical →
// recipient replies with a file (entry into the case payload's `docs`) →
// returning source, from the phrase alone, downloads it byte-identical.
// Adversarial assertions: the blob host sees only ciphertext of class size,
// the relays see no file metadata at all. Events always ride the in-memory
// relay — the relay path is live-proven by test/dialogue.mjs; --live swaps
// the blob transport for the real servers and cleans up after itself (BUD-02).

import { generateSecretKey, getPublicKey } from 'nostr-tools'
import { generateSeedWords, privateKeyFromSeedWords } from 'nostr-tools/nip06'
import { createServer } from 'node:http'
import { Relay } from '../lib/relay.mjs'
import { LocalRelay } from '../lib/liverelay.mjs'
import { wrapWithPow, unwrap, powBits } from '../shared/wrap.mjs'
import { localSigner, receiveGrants, latestGrants, fetchScope } from '../lib/nipxx.mjs'
import { bucketSize, pad, unpad } from '../shared/pad.mjs'
import { newFileKey, encryptBlob, decryptBlob, sha256hex, attachFile, fetchAttachment,
         validAttachment, deleteBlob, MAX_FILE_BYTES, DEFAULT_SERVERS } from '../shared/blossom.mjs'
import { loadDocket, upsertCase } from '../inbox/case.mjs'

const live = process.argv.includes('--live')
const BITS = 8                          // PoW is not under test here
console.log(live ? 'mode: LIVE Blossom servers' : 'mode: LOCAL mock Blossom')

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}
const same = (a, b) => a.length === b.length && a.every((x, i) => x === b[i])

/** Mock Blossom server (Nvelope's pattern): BUD-01 GET/PUT/DELETE, auth
 *  required to write, records every byte for the adversarial assertions. */
function mockBlossom() {
  const blobs = new Map()
  const seen = []                       // everything the operator could log
  const server = createServer((req, res) => {
    const chunks = []
    req.on('data', c => chunks.push(c))
    req.on('end', async () => {
      const body = new Uint8Array(Buffer.concat(chunks))
      seen.push({ method: req.method, url: req.url, auth: req.headers.authorization ?? null, body })
      const hash = req.url.slice(1)
      if (req.method === 'PUT' && req.url === '/upload') {
        if (!req.headers.authorization?.startsWith('Nostr ')) { res.writeHead(401); return res.end('auth required') }
        const sha = await sha256hex(body)
        blobs.set(sha, body)
        res.writeHead(201, { 'content-type': 'application/json' })
        return res.end(JSON.stringify({ sha256: sha, size: body.length }))
      }
      if (req.method === 'GET' && blobs.has(hash)) {
        res.writeHead(200, { 'content-type': 'application/octet-stream' })
        return res.end(Buffer.from(blobs.get(hash)))
      }
      if (req.method === 'DELETE') {
        if (!req.headers.authorization?.startsWith('Nostr ')) { res.writeHead(401); return res.end() }
        res.writeHead(blobs.delete(hash) ? 204 : 404)
        return res.end()
      }
      res.writeHead(404)
      res.end()
    })
  })
  return new Promise(r => server.listen(0, '127.0.0.1', () =>
    r({ url: `http://127.0.0.1:${server.address().port}/`, blobs, seen, server })))
}

const a = live ? null : await mockBlossom()
const b = live ? null : await mockBlossom()
const servers = live ? DEFAULT_SERVERS : [a.url, b.url]

const inner = new Relay()
const relay = new LocalRelay(inner)
const intake = generateSecretKey()
const intakePub = getPublicKey(intake)

// deterministic "files" with markers the adversarial section greps for;
// >64 KiB so the padding actually spans two content classes
const tipFile = Uint8Array.from({ length: 70_000 }, (_, i) => (i * 31 + 7) & 0xff)
tipFile.set(new TextEncoder().encode('MARKER: the harbour ledger, page seven'), 0)
const docFile = new TextEncoder().encode('MARKER: subpoena draft — do not circulate\n' + 'x'.repeat(500))

try {
  console.log('\n1. The pipeline itself: pad → encrypt → decrypt')
  check('64 KiB is the smallest class', bucketSize(1) === 65536)
  check('classes are 2^n × 64 KiB', bucketSize(65537) === 131072 && bucketSize(131073) === 262144)
  check('pad/unpad round-trips', same(unpad(pad(docFile)), docFile))
  const fk = newFileKey()
  const c0 = encryptBlob(fk, docFile)
  check('ciphertext sized by class alone', c0.length === 24 + 65536 + 16)
  check('decrypt round-trips', same(decryptBlob(fk, c0), docFile))
  const tampered = c0.slice(); tampered[60] ^= 1
  check('tampered ciphertext throws (Poly1305)',
    (() => { try { decryptBlob(fk, tampered); return false } catch { return true } })())

  console.log('\n2. Source attaches a file to the tip (manifest inside the rumor)')
  const words = generateSeedWords()
  const srcSk = privateKeyFromSeedWords(words)
  const srcPub = getPublicKey(srcSk)
  const entry = await attachFile(servers, localSigner(srcSk),
    { name: 'ledger-p7.pdf', mime: 'application/pdf', bytes: tipFile })
  check('entry has the spec §5 shape', validAttachment(entry)
    && entry.size_padded === 24 + 131072 + 16 && entry.mime === 'application/pdf')
  await relay.publish(await wrapWithPow(srcSk, intakePub, {
    kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
    content: JSON.stringify({ notegate: 1, text: 'see the attached ledger page', thread: null, files: [entry] }),
  }, BITS))

  console.log('\n3. Recipient: unwrap → fetch → verify → decrypt, byte-identical')
  const wraps = await relay.query({ kinds: [1059], '#p': [intakePub], limit: 500 })
  const rumors = wraps.filter(w => powBits(w) >= BITS).map(w => unwrap(intake, w))
  const tip = JSON.parse(rumors[0].content)
  check('the rumor carries the manifest entry', tip.files?.length === 1 && validAttachment(tip.files[0]))
  const gotTip = await fetchAttachment(tip.files[0])
  check('recipient downloads the exact bytes the source attached', same(gotTip, tipFile))

  console.log('\n4. Recipient replies with a file: entry into the case docs array')
  const docket = await loadDocket(relay, intake)
  const threadMsgs = [{ at: rumors[0].created_at, text: tip.text, files: tip.files }]
  const docEntry = await attachFile(servers, localSigner(intake),
    { name: 'subpoena-draft.txt', mime: 'text/plain', bytes: docFile })
  const { payload } = await upsertCase(relay, intake, docket, srcPub, {
    sourceMsgs: threadMsgs, replyText: 'draft attached — is the third name right?',
    docs: [{ ...docEntry, at: Math.floor(Date.now() / 1000) }], powPolicy: BITS,
  })
  check('case payload carries the doc entry', payload.docs.length === 1 && validAttachment(payload.docs[0]))
  check('source attachment survives the merge into the case messages',
    payload.messages.find(m => m.from === 'source')?.files?.length === 1)

  console.log('\n5. Returning source, from the phrase alone, downloads the doc')
  const retSk = privateKeyFromSeedWords(words)
  const g = latestGrants(await receiveGrants(relay, retSk)).find(x => x.publisher === intakePub)
  const view = await fetchScope(relay, g)
  check('case dereferences with docs intact', view.status === 'ok' && view.data.docs.length === 1)
  const gotDoc = await fetchAttachment(view.data.docs[0])
  check('source downloads the exact bytes the recipient attached', same(gotDoc, docFile))
  check('source re-downloads its own tip attachment from the case view',
    same(await fetchAttachment(view.data.messages.find(m => m.files)?.files[0]), tipFile))

  console.log('\n6. The 100 MB cap holds client-side, before any network')
  const putsBefore = live ? 0 : a.seen.filter(s => s.method === 'PUT').length
  const capErr = await attachFile(servers, localSigner(intake),
    { name: 'huge.bin', mime: 'application/octet-stream', bytes: new Uint8Array(MAX_FILE_BYTES + 1) })
    .then(() => null, err => err)
  check('oversized file is refused with clear messaging',
    capErr && capErr.message.includes('100 MB') && capErr.message.includes('huge.bin'))
  if (!live) check('…and nothing was uploaded',
    a.seen.filter(s => s.method === 'PUT').length === putsBefore)

  if (!live) {
    console.log('\n7. Adversarial: what the relays and the blob host saw')
    const relayBlob = JSON.stringify(inner.observerView()) + JSON.stringify(inner.events)
    check('relays see no file names or content', !relayBlob.includes('ledger-p7')
      && !relayBlob.includes('subpoena') && !relayBlob.includes('MARKER'))
    check('relays see no mime, hash, or servers', !relayBlob.includes('application/pdf')
      && !relayBlob.includes(entry.sha256_cipher) && !relayBlob.includes('sha256_cipher'))
    check('relays never see a filekey', !relayBlob.includes(entry.filekey)
      && !relayBlob.includes(docEntry.filekey))
    const hostBlob = [...a.seen, ...b.seen]
    const hostBytes = Buffer.concat(hostBlob.map(s => Buffer.from(s.body))).toString('latin1')
      + JSON.stringify(hostBlob.map(({ method, url, auth }) => ({ method, url, auth })))
    check('blob host never saw plaintext', !hostBytes.includes('MARKER')
      && !hostBytes.includes('harbour ledger') && !hostBytes.includes('subpoena'))
    check('blob host never saw a filekey', !hostBytes.includes(entry.filekey)
      && !hostBytes.includes(docEntry.filekey))
    check('every upload was ciphertext of class size only',
      hostBlob.filter(s => s.method === 'PUT')
        .every(s => [24 + 65536 + 16, 24 + 131072 + 16].includes(s.body.length)))
    a.server.close(); b.server.close()
  } else {
    console.log('\n7. Live hygiene: BUD-02 delete cleans up the test blobs')
    const d1 = await deleteBlob(entry.servers, localSigner(srcSk), entry.sha256_cipher)
    const d2 = await deleteBlob(docEntry.servers, localSigner(intake), docEntry.sha256_cipher)
    check('both test blobs deleted from at least one mirror', d1 >= 1 && d2 >= 1,
      `tip ${d1}/${entry.servers.length}, doc ${d2}/${docEntry.servers.length}`)
  }

  console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
  process.exit(failed === 0 ? 0 : 1)
} catch (err) {
  console.error('\n\x1b[31mAttach test aborted:\x1b[0m', err)
  process.exit(1)
}
