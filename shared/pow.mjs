// pow.mjs — NIP-13 proof of work: count leading zero bits of the event id;
// mine by iterating a nonce tag. Isomorphic; the submit page runs this in a
// Worker so the UI stays alive, tests run it inline with low difficulty.

import { getEventHash } from 'nostr-tools'

/** Leading zero bits of an event's id (NIP-13 difficulty). */
export function powBits(event) {
  let bits = 0
  for (let i = 0; i < event.id.length; i++) {
    const nibble = parseInt(event.id[i], 16)
    if (nibble === 0) { bits += 4; continue }
    bits += Math.clz32(nibble) - 28
    break
  }
  return bits
}

/**
 * Mine `bits` of PoW on an unsigned event by iterating a ["nonce", n, bits]
 * tag (NIP-13). Async: yields to the event loop periodically so browser UIs
 * stay responsive; onProgress(attempts) fires every batch.
 */
export async function minePow(unsigned, bits, onProgress) {
  const event = { ...unsigned, tags: [...unsigned.tags, ['nonce', '0', String(bits)]] }
  const nonceTag = event.tags[event.tags.length - 1]
  let n = 0
  for (;;) {
    for (let i = 0; i < 5000; i++) {
      nonceTag[1] = String(n++)
      event.id = getEventHash(event)
      if (powBits(event) >= bits) return event
    }
    onProgress?.(n)
    await new Promise(r => setTimeout(r, 0))
    // keep created_at fresh-ish on long mines without breaking NIP-59 fuzz
  }
}
