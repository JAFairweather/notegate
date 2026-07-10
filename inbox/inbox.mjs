// inbox.mjs — the newsroom side. Intake key in sessionStorage (Nvelope's
// login pattern), kind-0 identity publish, share-URL builder, and the tip
// list: poll kind-1059 wraps addressed to the intake key, apply the NIP-13
// PoW gate BEFORE any decryption, unwrap survivors, thread by the rumor's
// ephemeral pubkey.
//
// M2 dialogue: replying opens a per-source case (case.mjs) — a 30440 scope
// granted to the source's ephemeral key, recorded in the Grant Index, which
// IS the case docket. Once a case exists its open/archived status lives in
// the payload and docket (shared with the source); caseless threads keep the
// local-only archive triage from M1.

import { finalizeEvent, generateSecretKey, getPublicKey, nip19 } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { unwrap, powBits } from '../shared/wrap.mjs'
import { loadDocket, upsertCase, fetchCase, caseOutOfSync } from './case.mjs'

const RELAYS = ['wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net']
const POW_BITS = 20               // gate: wraps below this are never decrypted
const POLL_MS = 30_000

const $ = (id) => document.getElementById(id)
const short = (pk) => { const n = nip19.npubEncode(pk); return n.slice(0, 12) + '…' + n.slice(-4) }
const when = (ts) => new Date(ts * 1000).toLocaleString()
const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')

const state = {
  relay: null, sk: null, me: null,
  threads: new Map(),             // source pubkey → [{ at, text }] (newest thread first at render)
  archived: new Set(),            // caseless threads only, persisted in localStorage
  docket: { index: { issued: [], received: [] }, cases: new Map() },  // Grant Index = case docket
  caseData: new Map(),            // source pubkey → decrypted case payload
  gated: 0,                       // wraps rejected by the PoW gate (never decrypted)
  showArchived: false,
  seen: new Set(),                // wrap ids already processed
  timer: null,
}

const caseOf = (src) => state.docket.cases.get(src)
const isArchived = (src) =>
  caseOf(src) ? caseOf(src).status === 'archived' : state.archived.has(src)

function parseKey(input) {
  const s = input.trim()
  if (/^[0-9a-f]{64}$/i.test(s)) return Uint8Array.from(s.match(/../g), h => parseInt(h, 16))
  const { type, data } = nip19.decode(s)
  if (type !== 'nsec') throw new Error('not an nsec')
  return data
}

// --- triage state (local only) ---------------------------------------------
const archiveKey = () => `notegate-archived-${state.me}`
const loadArchived = () => {
  try { state.archived = new Set(JSON.parse(localStorage.getItem(archiveKey()) ?? '[]')) }
  catch { state.archived = new Set() }
}
const saveArchived = () =>
  localStorage.setItem(archiveKey(), JSON.stringify([...state.archived]))

// --- login ------------------------------------------------------------------
async function login(sk) {
  state.sk = sk
  state.me = getPublicKey(sk)
  sessionStorage.setItem('notegate-login', hexOf(sk))
  state.relay ??= new LiveRelay(RELAYS)
  loadArchived()
  try { await refreshDocket() } catch { /* no index yet — first run */ }
  $('login').style.display = 'none'
  $('setup').style.display = 'block'
  $('me').style.display = 'flex'
  $('status').style.display = 'block'
  const npub = nip19.npubEncode(state.me)
  $('my-npub').textContent = short(state.me)
  $('my-npub').onclick = () => navigator.clipboard.writeText(npub)
  $('share-url').value = new URL('../submit/', location.href).href + '#' + npub
  $('share-row').style.display = 'flex'
  // prefill the tip line name from an existing kind-0, if any
  state.relay.query({ kinds: [0], authors: [state.me], limit: 1 })
    .then(([ev]) => { if (ev && !$('org').value) $('org').value = JSON.parse(ev.content).name ?? '' })
    .catch(() => {})
  await loadTips()
  clearInterval(state.timer)
  state.timer = setInterval(loadTips, POLL_MS)
}

// --- identity publish --------------------------------------------------------
$('publish').onclick = async () => {
  const name = $('org').value.trim()
  if (!name) { $('setup-msg').textContent = 'Give the tip line a name first.'; return }
  $('publish').disabled = true
  $('setup-msg').textContent = 'publishing…'
  try {
    const ev = finalizeEvent({
      kind: 0, created_at: Math.floor(Date.now() / 1000), tags: [],
      content: JSON.stringify({ name, about: 'Secure tip line (Notegate)' }),
    }, state.sk)
    const { acks, of } = await state.relay.publish(ev)
    $('setup-msg').textContent = `published to ${acks}/${of} relays — sources now see “${name}”.`
  } catch (err) { $('setup-msg').textContent = `publish failed: ${err.message}` }
  $('publish').disabled = false
}
$('copy-url').onclick = () => {
  navigator.clipboard.writeText($('share-url').value)
  $('setup-msg').textContent = 'share URL copied.'
}

// --- the case docket (kind 10440 — the ONLY case store) ----------------------
async function refreshDocket() {
  state.docket = await loadDocket(state.relay, state.sk)
  await Promise.all([...state.docket.cases.entries()].map(async ([src, c]) => {
    const res = await fetchCase(state.relay, state.me, c)
    if (res.status === 'ok') state.caseData.set(src, res.data)
  }))
}

// --- the inbox pipeline: poll → PoW gate → unwrap → thread -------------------
async function loadTips() {
  $('status').textContent = 'polling relays for tips…'
  let wraps
  try { wraps = await state.relay.query({ kinds: [1059], '#p': [state.me], limit: 500 }) }
  catch (err) { $('status').textContent = `relay error: ${err.message}`; return }
  for (const wrap of wraps) {
    if (state.seen.has(wrap.id)) continue
    state.seen.add(wrap.id)
    // spam gate: judge the wrap alone, BEFORE any decryption
    if (powBits(wrap) < POW_BITS) { state.gated++; continue }
    let rumor
    try { rumor = unwrap(state.sk, wrap) } catch { continue }   // not for us / malformed
    if (rumor.kind !== 14) continue                             // tips and replies only
    let text
    try {
      const c = JSON.parse(rumor.content)
      text = typeof c.text === 'string' ? c.text : rumor.content
    } catch { text = rumor.content }
    const msgs = state.threads.get(rumor.pubkey) ?? []
    msgs.push({ at: rumor.created_at, text })
    msgs.sort((a, b) => a.at - b.at)
    state.threads.set(rumor.pubkey, msgs)
  }
  // keep open cases in sync: new source messages get merged into the case
  // payload (free republish, same key) so the source's own view is complete
  for (const [src, msgs] of state.threads) {
    if (!caseOf(src) || !caseOutOfSync(state.caseData.get(src), msgs)) continue
    try {
      const { payload } = await upsertCase(state.relay, state.sk, state.docket, src,
        { sourceMsgs: msgs, powPolicy: POW_BITS })
      state.caseData.set(src, payload)
    } catch { /* transient relay failure — retried next poll */ }
  }
  render()
}

function render() {
  const threads = [...state.threads.entries()]
    .map(([src, msgs]) => ({ src, msgs, latest: msgs[msgs.length - 1].at }))
    .sort((a, b) => b.latest - a.latest)
  const live = threads.filter(t => !isArchived(t.src))
  const arch = threads.filter(t => isArchived(t.src))
  const shown = state.showArchived ? [...live, ...arch] : live

  $('status').innerHTML = `${live.length} open thread${live.length === 1 ? '' : 's'}, ` +
    `${arch.length} archived. <span id="gate"></span>`
  $('status').querySelector('#gate').textContent =
    `PoW gate: ${state.gated} wrap${state.gated === 1 ? '' : 's'} rejected without decryption.`

  $('archtoggle').style.display = arch.length ? 'block' : 'none'
  $('show-arch').textContent = state.showArchived
    ? 'hide archived' : `show ${arch.length} archived`

  const sect = $('threads')
  sect.style.display = 'block'
  sect.textContent = ''
  if (!shown.length) {
    const d = document.createElement('div')
    d.className = 'empty'
    d.textContent = threads.length
      ? 'Nothing open. Archived threads are hidden.'
      : 'No tips yet. Share the URL above — tips appear here as sources send them.'
    sect.append(d)
    return
  }
  for (const t of shown) sect.append(threadCard(t))
}

function threadCard({ src, msgs }) {
  const isArch = isArchived(src)
  const c = caseOf(src)
  const card = document.createElement('div')
  card.className = 'thread' + (isArch ? ' archived' : '')

  const head = document.createElement('div')
  head.className = 'head'
  const id = document.createElement('span')
  id.className = 'src'
  id.title = 'ephemeral source id — the thread, not a person'
  id.textContent = short(src)
  const ts = document.createElement('span')
  ts.className = 'when'
  const sp = document.createElement('span')
  sp.className = 'spacer'
  const chip = document.createElement('span')
  chip.className = 'case' + (c && !isArch ? ' open' : '')
  chip.textContent = c ? `case ${c.status}` : 'no case yet'
  chip.title = c
    ? 'the source reads this dialogue with their recovery phrase'
    : 'replying opens an encrypted case file this source can read'
  const btn = document.createElement('button')
  btn.textContent = isArch ? 'Unarchive' : 'Archive'
  btn.onclick = async () => {
    btn.disabled = true
    if (c) {
      try {
        const { payload } = await upsertCase(state.relay, state.sk, state.docket, src,
          { sourceMsgs: msgs, status: isArch ? 'open' : 'archived', powPolicy: POW_BITS })
        state.caseData.set(src, payload)
      } catch (err) { $('status').textContent = `archive failed: ${err.message}` }
    } else {
      isArch ? state.archived.delete(src) : state.archived.add(src)
      saveArchived()
    }
    render()
  }
  head.append(id, ts, sp, chip, btn)
  card.append(head)

  // the dialogue: source messages from the wraps, ours from the case payload
  const mine = (state.caseData.get(src)?.messages ?? []).filter(m => m.from === 'recipient')
  const dialogue = [...msgs.map(m => ({ ...m, from: 'source' })), ...mine]
    .sort((a, b) => a.at - b.at)
  ts.textContent = when(dialogue[dialogue.length - 1].at)
  for (const m of dialogue) {
    const div = document.createElement('div')
    div.className = 'tipmsg' + (m.from === 'recipient' ? ' mine' : '')
    const w = document.createElement('div')
    w.className = 'when'
    w.textContent = (m.from === 'recipient' ? 'you · ' : 'source · ') + when(m.at)
    const b = document.createElement('div')
    b.className = 'body'
    b.textContent = m.text          // textContent: tips are hostile input
    div.append(w, b)
    card.append(div)
  }

  // reply box — first reply mints the case scope + grant + docket entry
  const row = document.createElement('div')
  row.className = 'replyrow'
  const ta = document.createElement('textarea')
  ta.placeholder = c ? 'Reply…'
    : 'Reply — this opens an encrypted case file the source can read with their recovery phrase.'
  const rbtn = document.createElement('button')
  rbtn.textContent = 'Reply'
  rbtn.onclick = async () => {
    const text = ta.value.trim()
    if (!text) return
    rbtn.disabled = true
    rbtn.textContent = 'Publishing…'
    try {
      const { payload } = await upsertCase(state.relay, state.sk, state.docket, src,
        { sourceMsgs: msgs, replyText: text, powPolicy: POW_BITS })
      state.caseData.set(src, payload)
      render()
    } catch (err) {
      rbtn.disabled = false
      rbtn.textContent = 'Reply'
      $('status').textContent = `reply failed: ${err.message}`
    }
  }
  row.append(ta, rbtn)
  card.append(row)
  return card
}

// --- wiring -------------------------------------------------------------------
$('go').onclick = () => {
  try { login(parseKey($('nsec').value)) }
  catch { $('err').textContent = 'Expected nsec1… or 64 hex chars.' }
}
$('nsec').onkeydown = (e) => { if (e.key === 'Enter') $('go').onclick() }
$('gen').onclick = () => {
  // The key is shown in-page (selectable, with a Copy button) — an alert()
  // can't be copied, and this key is the whole tip line.
  const k = generateSecretKey()
  $('err').textContent = ''
  $('newkey').style.display = ''
  $('newkey-nsec').textContent = nip19.nsecEncode(k)
  $('newkey-copy').onclick = async () => {
    await navigator.clipboard.writeText(nip19.nsecEncode(k))
    $('newkey-copy').textContent = 'Copied \u2713'
    setTimeout(() => { $('newkey-copy').textContent = 'Copy' }, 2000)
  }
  $('newkey-continue').onclick = () => login(k)
}
$('refresh').onclick = async () => {
  try { await refreshDocket() } catch { /* keep the cached docket */ }
  loadTips()
}
$('show-arch').onclick = () => { state.showArchived = !state.showArchived; render() }
$('logout').onclick = () => {
  sessionStorage.removeItem('notegate-login')
  clearInterval(state.timer)
  location.reload()
}

const saved = sessionStorage.getItem('notegate-login')
if (saved) login(Uint8Array.from(saved.match(/../g), h => parseInt(h, 16)))
