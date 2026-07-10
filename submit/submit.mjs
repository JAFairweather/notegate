// submit.mjs — the source side. Ephemeral key from BIP-39 words (the words
// ARE the reply channel), PoW-mined gift wrap, per-relay jittered publish.
// This page must make zero network requests except to relays.

import { nip06, nip19 } from 'nostr-tools'
import { LiveRelay } from '../lib/liverelay.mjs'
import { wrapWithPow } from '../shared/wrap.mjs'

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
    const skHex = nip06.privateKeyFromSeedWords(words)
    const sk = Uint8Array.from(skHex.match(/../g), h => parseInt(h, 16))
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
