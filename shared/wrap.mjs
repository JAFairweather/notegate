// wrap.mjs — NIP-59 gift wrap for arbitrary rumors, with NIP-13 proof of
// work mined on the OUTER wrap (the spam gate: relays and the inbox judge
// the wrap alone, before any decryption). Same construction as the protocol
// lib's internal grant wrapping; no new cryptography.

import { finalizeEvent, generateSecretKey, getEventHash, getPublicKey, nip44, verifyEvent } from 'nostr-tools'
import { minePow, powBits } from './pow.mjs'

const fuzz = () => Math.floor(Date.now() / 1000) - Math.floor(Math.random() * 2 * 24 * 60 * 60)

/**
 * Seal `rumor` (unsigned, deniable) from `senderSk` and gift-wrap it to
 * `recipientPub`, mining `bits` of PoW on the wrap. Returns the signed wrap.
 */
export async function wrapWithPow(senderSk, recipientPub, rumor, bits = 0, onProgress) {
  rumor.pubkey = getPublicKey(senderSk)
  rumor.id = getEventHash(rumor)
  const sealKey = nip44.v2.utils.getConversationKey(senderSk, recipientPub)
  const seal = finalizeEvent({
    kind: 13, created_at: fuzz(), tags: [],
    content: nip44.v2.encrypt(JSON.stringify(rumor), sealKey),
  }, senderSk)
  const ephemeral = generateSecretKey()
  const unsigned = {
    kind: 1059, created_at: fuzz(),
    pubkey: getPublicKey(ephemeral),
    tags: [['p', recipientPub]],
    content: nip44.v2.encrypt(JSON.stringify(seal),
      nip44.v2.utils.getConversationKey(ephemeral, recipientPub)),
  }
  const mined = bits > 0 ? await minePow(unsigned, bits, onProgress) : unsigned
  return finalizeEvent(mined, ephemeral)
}

/**
 * Unwrap a gift wrap addressed to `recipientSk`; returns the verified rumor.
 * Callers should check powBits(wrap) BEFORE calling — rejection is cheap,
 * decryption is not.
 */
export function unwrap(recipientSk, wrap) {
  const seal = JSON.parse(nip44.v2.decrypt(wrap.content,
    nip44.v2.utils.getConversationKey(recipientSk, wrap.pubkey)))
  if (seal.kind !== 13 || !verifyEvent(seal)) throw new Error('bad seal')
  const rumor = JSON.parse(nip44.v2.decrypt(seal.content,
    nip44.v2.utils.getConversationKey(recipientSk, seal.pubkey)))
  if (rumor.pubkey !== seal.pubkey) throw new Error('seal/rumor pubkey mismatch')
  return rumor
}

export { powBits }
