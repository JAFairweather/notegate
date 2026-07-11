// submit.mjs — the source side. Ephemeral key from BIP-39 words (the words
// ARE the reply channel), PoW-mined gift wrap, per-relay jittered publish.
// M2: the returning-source path re-derives that key from the phrase, polls
// its gift wraps for a case grant, and dereferences the case scope — the
// dialogue — with the ability to reply at the recipient's PoW price.
// M3: attachments — files are encrypted on-device under a random filekey and
// uploaded to Blossom hosts as ciphertext; the manifest entry rides INSIDE
// the encrypted rumor. This page must make zero network requests except to
// relays and (only when files are attached or downloaded) the blob hosts.

import { getPublicKey, nip19 } from 'nostr-tools'
// nip06 is not re-exported by the esm.sh root bundle — import the subpath
import * as nip06 from 'nostr-tools/nip06'
import { LiveRelay } from '../lib/liverelay.mjs'
import { wrapWithPow } from '../shared/wrap.mjs'
import { publishJittered, currentMaxJitterMs } from '../shared/jitter.mjs'
import { receiveGrants, latestGrants, fetchScope, localSigner } from '../lib/nipxx.mjs'
import { attachFile, fetchAttachment, validAttachment, sha256hex,
         DEFAULT_SERVERS, MAX_FILE_BYTES } from '../shared/blossom.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const POW_BITS = 20
const $ = (id) => document.getElementById(id)

let intakePub = null
const relay = new LiveRelay(RELAYS)                       // queries (profile, grants, scopes)
const pubRelays = RELAYS.map(u => new LiveRelay([u]))     // publishes: one connection per relay, jittered independently

/** Publish a wrap with per-relay 0–90s jitter, narrating honestly into `el`. */
async function publishStaggered(wrap, el) {
  const secs = Math.round(currentMaxJitterMs() / 1000)
  const note = (done) =>
    `staggering publication to resist timing correlation — each relay gets ` +
    `an independent random delay of up to ${secs}s (${done}/${pubRelays.length} done). ` +
    `Keep this tab open until it finishes.`
  el.textContent = note(0)
  return publishJittered(pubRelays, wrap, { onProgress: (n) => { el.textContent = note(n) } })
}

// --- attachments (M3) --------------------------------------------------------

/** Encrypt-and-upload every file chosen in `input`; returns manifest entries.
 *  The 100 MB cap is enforced before any bytes leave this device. */
async function uploadFiles(input, sk, statusEl) {
  const files = [...(input?.files ?? [])]
  const entries = []
  for (const [i, f] of files.entries()) {
    if (f.size > MAX_FILE_BYTES) throw new Error(
      `“${f.name}” is ${(f.size / 1048576).toFixed(1)} MB — the limit is 100 MB per file`)
    statusEl.textContent = `encrypting & uploading “${f.name}” (${i + 1}/${files.length})…`
    entries.push(await attachFile(DEFAULT_SERVERS, localSigner(sk),
      { name: f.name, mime: f.type || 'application/octet-stream',
        bytes: new Uint8Array(await f.arrayBuffer()) }))
  }
  return entries
}

/** Download chip: fetch → hash-verify → decrypt → save. Hostile names are
 *  fine — textContent only, and `download` never navigates. */
function fileChip(entry) {
  const btn = document.createElement('button')
  btn.type = 'button'
  btn.className = 'filechip'
  btn.textContent = `↓ ${entry.name}`
  btn.title = 'fetch, verify, decrypt, save'
  btn.onclick = async () => {
    btn.disabled = true
    btn.textContent = 'fetching…'
    try {
      const bytes = await fetchAttachment(entry)
      btn.dataset.sha = await sha256hex(bytes)          // E2E verification hook
      const a = document.createElement('a')
      a.href = URL.createObjectURL(new Blob([bytes], { type: entry.mime || 'application/octet-stream' }))
      a.download = entry.name || 'file'
      a.click()
      setTimeout(() => URL.revokeObjectURL(a.href), 60_000)
      btn.textContent = `↓ ${entry.name}`
    } catch (err) { btn.textContent = `failed: ${String(err.message).slice(0, 60)}` }
    btn.disabled = false
  }
  return btn
}

/** Append validated attachment chips for `entries` to `el`. */
function renderFiles(el, entries) {
  for (const e of (entries ?? []).filter(validAttachment)) el.append(fileChip(e))
}

// intake npub rides the URL fragment — never a query string
try {
  const { type, data } = nip19.decode(location.hash.slice(1))
  if (type !== 'npub') throw new Error()
  intakePub = data
  $('to').innerHTML = 'to: <b>…</b>'
  relay.query({ kinds: [0], authors: [intakePub], limit: 1 }).then(([ev]) => {
    const name = ev ? (JSON.parse(ev.content).name ?? 'unnamed recipient') : 'unknown recipient'
    $('to').innerHTML = `to: <b></b>`
    $('to').querySelector('b').textContent = name
  }).catch(() => { $('to').textContent = 'to: (could not load recipient profile)' })
} catch {
  $('to').innerHTML = '<span class="err">No recipient in this link. Ask for a link ending in #npub1…</span>'
  $('send').disabled = true
}

$('f').onsubmit = async (e) => {
  e.preventDefault()
  const text = $('tip').value.trim()
  if (!text || !intakePub) return
  $('send').disabled = true
  try {
    // BIP-39 words are the source's whole identity and reply channel
    const words = nip06.generateSeedWords()
    const sk = nip06.privateKeyFromSeedWords(words)   // Uint8Array in nostr-tools 2.x
    // files first: encrypted on-device, uploaded as ciphertext; only the
    // manifest entries enter the rumor, and only the rumor is ever readable
    const files = await uploadFiles($('tip-files'), sk, $('status'))
    const rumor = {
      kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ notegate: 1, text, thread: null,
        ...(files.length ? { files } : {}) }),
    }
    $('status').textContent = `mining proof of work (${POW_BITS} bits) — this is the spam gate, give it a moment…`
    const wrap = await wrapWithPow(sk, intakePub, rumor, POW_BITS,
      (n) => { $('status').textContent = `mining proof of work… ${Math.round(n / 1000)}k attempts` })
    // per-relay jitter (spec §6): each relay gets its own 0–90s random delay
    await publishStaggered(wrap, $('status'))
    $('status').textContent = ''
    $('f').style.display = 'none'
    $('after').style.display = 'block'
    $('phrase').textContent = words
    sk.fill(0)          // memory hygiene: the phrase re-derives it; this copy is done
  } catch (err) {
    $('status').innerHTML = `<span class="err"></span>`
    $('status').querySelector('.err').textContent = `failed: ${err.message} — nothing was sent in the clear`
    $('send').disabled = false
  }
}

// --- returning source: the words ARE the identity ---------------------------
let retSk = null            // ephemeral key re-derived from the phrase
let retTo = null            // where replies go: fragment npub, or the grant's publisher
let retPow = POW_BITS       // the recipient's price, read from the case payload

$('ret').onclick = () => {
  $('f').style.display = 'none'
  $('after').style.display = 'none'
  $('ret-link').style.display = 'none'
  $('retsec').style.display = 'block'
  $('words').focus()
}
$('ret-open').onclick = () => openDialogue()
$('words').onkeydown = (e) => { if (e.key === 'Enter') openDialogue() }
$('dlg-refresh').onclick = () => loadDialogue()

async function openDialogue() {
  try {
    retSk = nip06.privateKeyFromSeedWords($('words').value.trim().toLowerCase())
  } catch {
    $('ret-status').innerHTML = '<span class="err">That is not a valid recovery phrase — twelve words, exactly as shown after sending.</span>'
    return
  }
  await loadDialogue()
}

async function loadDialogue() {
  $('ret-status').textContent = 'checking the relays for a reply channel…'
  let g = null
  try {
    // the lib does the work: unwrap kind-440 grants addressed to this key
    const grants = latestGrants(await receiveGrants(relay, retSk))
    g = grants.find(x => !intakePub || x.publisher === intakePub) ?? grants[0] ?? null
  } catch (err) {
    $('ret-status').textContent = `relay error: ${err.message}`
    return
  }
  retTo = intakePub ?? g?.publisher ?? null
  let messages = [], docs = [], note = ''
  if (!g) {
    note = 'No reply yet. If your message was answered, a private case file would appear here — check back later. You can still send a follow-up below.'
  } else {
    const res = await fetchScope(relay, g)
    if (res.status === 'ok') {
      retPow = res.data.pow ?? POW_BITS
      messages = res.data.messages ?? []
      docs = res.data.docs ?? []
      if (res.data.status === 'archived')
        note = 'The recipient archived this conversation — a reply may go unread.'
    } else if (res.status === 'stale') {
      note = 'The recipient closed this conversation: your access was rotated out. There will be no further updates on this channel.'
    } else {
      note = 'A reply channel exists, but the case file has not reached these relays yet — check again shortly.'
    }
  }
  renderDialogue(messages, note, docs)
}

function renderDialogue(messages, note, docs = []) {
  $('ret-status').textContent = note
  $('dlg').style.display = 'block'
  const box = $('dlg-msgs')
  box.textContent = ''
  for (const m of messages) {
    const div = document.createElement('div')
    div.className = 'msg' + (m.from === 'source' ? ' me' : '')
    const who = document.createElement('div')
    who.className = 'who'
    who.textContent = (m.from === 'source' ? 'you' : 'recipient') + ' · ' +
      new Date(m.at * 1000).toLocaleString()
    const body = document.createElement('div')
    body.className = 'body'
    body.textContent = m.text       // hostile input on both sides
    div.append(who, body)
    renderFiles(div, m.files)
    box.append(div)
  }
  const docsBox = $('dlg-docs')
  docsBox.textContent = ''
  if ((docs ?? []).some(validAttachment)) {
    const h = document.createElement('div')
    h.className = 'docs-head'
    h.textContent = 'documents from the recipient'
    docsBox.append(h)
    renderFiles(docsBox, docs)
  }
  $('reply-send').disabled = !retTo
  if (!retTo) $('reply-status').textContent =
    'Cannot reply from this link — open the tip line’s full URL (ending in #npub1…).'
}

$('reply-send').onclick = async () => {
  const text = $('reply').value.trim()
  if ((!text && !$('reply-files').files.length) || !retSk || !retTo) return
  $('reply-send').disabled = true
  try {
    const files = await uploadFiles($('reply-files'), retSk, $('reply-status'))
    const rumor = {
      kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ notegate: 1, text, thread: getPublicKey(retSk),
        ...(files.length ? { files } : {}) }),
    }
    $('reply-status').textContent = `mining proof of work (${retPow} bits) — the same spam gate as the first message…`
    const wrap = await wrapWithPow(retSk, retTo, rumor, retPow,
      (n) => { $('reply-status').textContent = `mining proof of work… ${Math.round(n / 1000)}k attempts` })
    await publishStaggered(wrap, $('reply-status'))
    $('reply').value = ''
    $('reply-files').value = ''
    $('reply-status').textContent = 'sent. It joins the case file when the recipient next reads their inbox.'
  } catch (err) {
    $('reply-status').innerHTML = '<span class="err"></span>'
    $('reply-status').querySelector('.err').textContent =
      `failed: ${err.message} — nothing was sent in the clear`
  }
  $('reply-send').disabled = false
}
