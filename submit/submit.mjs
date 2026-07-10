// submit.mjs — the source side. Ephemeral key from BIP-39 words (the words
// ARE the reply channel), PoW-mined gift wrap, per-relay jittered publish.
// M2: the returning-source path re-derives that key from the phrase, polls
// its gift wraps for a case grant, and dereferences the case scope — the
// dialogue — with the ability to reply at the recipient's PoW price.
// This page must make zero network requests except to relays.

import { getPublicKey, nip19 } from 'nostr-tools'
// nip06 is not re-exported by the esm.sh root bundle — import the subpath
import * as nip06 from 'nostr-tools/nip06'
import { LiveRelay } from '../lib/liverelay.mjs'
import { wrapWithPow } from '../shared/wrap.mjs'
import { receiveGrants, latestGrants, fetchScope } from '../lib/nipxx.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const POW_BITS = 20
const $ = (id) => document.getElementById(id)

let intakePub = null
const relay = new LiveRelay(RELAYS)

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
    const rumor = {
      kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ notegate: 1, text, thread: null }),
    }
    $('status').textContent = `mining proof of work (${POW_BITS} bits) — this is the spam gate, give it a moment…`
    const wrap = await wrapWithPow(sk, intakePub, rumor, POW_BITS,
      (n) => { $('status').textContent = `mining proof of work… ${Math.round(n / 1000)}k attempts` })
    // per-relay jitter: publish to each relay on its own randomized delay
    $('status').textContent = 'publishing with randomized delays…'
    await new Promise(r => setTimeout(r, Math.random() * 3000))   // M1: short jitter; 0–90s at M4
    await relay.publish(wrap)
    $('f').style.display = 'none'
    $('after').style.display = 'block'
    $('phrase').textContent = words
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
  let messages = [], note = ''
  if (!g) {
    note = 'No reply yet. If your message was answered, a private case file would appear here — check back later. You can still send a follow-up below.'
  } else {
    const res = await fetchScope(relay, g)
    if (res.status === 'ok') {
      retPow = res.data.pow ?? POW_BITS
      messages = res.data.messages ?? []
      if (res.data.status === 'archived')
        note = 'The recipient archived this conversation — a reply may go unread.'
    } else if (res.status === 'stale') {
      note = 'The recipient closed this conversation: your access was rotated out. There will be no further updates on this channel.'
    } else {
      note = 'A reply channel exists, but the case file has not reached these relays yet — check again shortly.'
    }
  }
  renderDialogue(messages, note)
}

function renderDialogue(messages, note) {
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
    box.append(div)
  }
  $('reply-send').disabled = !retTo
  if (!retTo) $('reply-status').textContent =
    'Cannot reply from this link — open the tip line’s full URL (ending in #npub1…).'
}

$('reply-send').onclick = async () => {
  const text = $('reply').value.trim()
  if (!text || !retSk || !retTo) return
  $('reply-send').disabled = true
  try {
    const rumor = {
      kind: 14, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ notegate: 1, text, thread: getPublicKey(retSk) }),
    }
    $('reply-status').textContent = `mining proof of work (${retPow} bits) — the same spam gate as the first message…`
    const wrap = await wrapWithPow(retSk, retTo, rumor, retPow,
      (n) => { $('reply-status').textContent = `mining proof of work… ${Math.round(n / 1000)}k attempts` })
    $('reply-status').textContent = 'publishing with randomized delay…'
    await new Promise(r => setTimeout(r, Math.random() * 3000))
    await relay.publish(wrap)
    $('reply').value = ''
    $('reply-status').textContent = 'sent. It joins the case file when the recipient next reads their inbox.'
  } catch (err) {
    $('reply-status').innerHTML = '<span class="err"></span>'
    $('reply-status').querySelector('.err').textContent =
      `failed: ${err.message} — nothing was sent in the clear`
  }
  $('reply-send').disabled = false
}
