// rotate.mjs — intake key rotation with a sunset window (spec §4.5:
// "rotate the intake key itself — publish new npub in kind-0 and on the
// submit page; keep decrypting the old key during a configurable sunset
// window; both keys' Grant Indexes merge in the UI").
//
// The retired key rides INSIDE the new key's Grant Index (kind 10440,
// NIP-44-encrypted to self) under `notegate_retired` — ciphertext on the
// wire, and the whole arrangement reconstitutes from the new nsec alone on
// any device, like everything else in Notegate. When the sunset window
// expires, pruning the entry from the index IS deletion of the old key
// material: the index is the only place it exists.
//
// Isomorphic: no DOM; runs in Node tests and the browser.

import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools'
import { loadGrantIndex, saveGrantIndex } from '../lib/nipxx.mjs'

export const DEFAULT_SUNSET_DAYS = 30

const nowSec = () => Math.floor(Date.now() / 1000)
const hexOf = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
export const skFromHex = (s) => Uint8Array.from(s.match(/../g), h => parseInt(h, 16))

/** The index's still-active retired keys: [{ pk, sk, rotated_at, until }]. */
export const retiredKeys = (index, now = nowSec()) =>
  (index?.notegate_retired ?? []).filter(e =>
    Number(e.until) > now && /^[0-9a-f]{64}$/.test(e.sk ?? '') && /^[0-9a-f]{64}$/.test(e.pk ?? ''))

/**
 * Mint a fresh intake keypair; record the old key (and any still-active
 * previously-retired keys — rotations chain) in the NEW key's index; publish
 * the new key's kind-0 so the new share URL renders the same tip-line name.
 * Returns { newSk, index }. The caller owns showing the new nsec + share URL
 * and re-protecting the key at rest.
 */
export async function rotateIntakeKey(relay, oldSk,
    { name, sunsetDays = DEFAULT_SUNSET_DAYS, now = nowSec() } = {}) {
  const newSk = generateSecretKey()
  let oldIndex = null
  try { oldIndex = await loadGrantIndex(relay, oldSk) } catch { /* none yet */ }
  const index = {
    issued: [], received: [],
    notegate_retired: [
      { pk: getPublicKey(oldSk), sk: hexOf(oldSk), rotated_at: now, until: now + sunsetDays * 86400 },
      ...retiredKeys(oldIndex, now),
    ],
  }
  await saveGrantIndex(relay, newSk, index)
  if (name) await relay.publish(finalizeEvent({
    kind: 0, created_at: nowSec(), tags: [],
    content: JSON.stringify({ name, about: 'Secure tip line (Notegate)' }),
  }, newSk))
  return { newSk, index }
}

/**
 * Sunset enforcement, run on every login: drop expired retired keys and
 * re-save the index. Returns the surviving entries. After this, tips sent
 * to an expired key's share URL are undecryptable here — the channel is
 * closed, which is what the sunset window promised.
 */
export async function pruneRetired(relay, sk, index, now = nowSec()) {
  const before = (index?.notegate_retired ?? []).length
  const keep = retiredKeys(index, now)
  if (keep.length !== before) {
    index.notegate_retired = keep
    await saveGrantIndex(relay, sk, index)
  }
  return keep
}
