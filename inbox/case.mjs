// case.mjs — the dialogue layer (M2). One kind-30440 *case scope* per source,
// keyed by the source's ephemeral pubkey; a kind-440 grant hands the scope key
// to that pubkey; and the kind-10440 Grant Index IS the case docket — there is
// deliberately no other case store, so the whole docket reconstitutes from the
// intake nsec alone on any device.
//
// Isomorphic: imports only the vendored protocol lib, runs in Node and browser.

import { getPublicKey } from 'nostr-tools'
import {
  publishScope, grant, fetchScope, newScopeKey,
  loadGrantIndex, saveGrantIndex, toIssuedEntry, fromIssuedEntry,
} from '../lib/nipxx.mjs'

/** Opaque case-scope id: 16 random bytes, hex. Semantic names (or anything
 *  derived from the source's pubkey) would let relays link case to thread. */
export const opaqueId = () =>
  Array.from(crypto.getRandomValues(new Uint8Array(16)), b => b.toString(16).padStart(2, '0')).join('')

/**
 * Load the docket. Each issued entry's single grantee is the source's
 * ephemeral pubkey — that IS the thread id, so the mapping thread→case
 * needs no extra storage. Returns { index, cases: Map(sourcePub → caseRec) }.
 */
export async function loadDocket(relay, intakeSk) {
  const index = await loadGrantIndex(relay, intakeSk)
  const cases = new Map()
  for (const e of index.issued ?? []) {
    const src = e.grantees?.[0]
    if (src) cases.set(src, { ...fromIssuedEntry(e), status: e.status ?? 'open' })
  }
  return { index, cases }
}

/** Rewrite the issued side of the index from the case map; preserve `received`. */
export async function saveDocket(relay, intakeSk, docket) {
  docket.index.issued = [...docket.cases.entries()]
    .map(([src, c]) => ({ ...toIssuedEntry(c, [src]), status: c.status }))
  return saveGrantIndex(relay, intakeSk, docket.index)
}

/** Dereference one case scope (the recipient reading their own record). */
export async function fetchCase(relay, intakePub, c) {
  return fetchScope(relay, {
    publisher: intakePub, scopeId: c.scopeId, generation: c.generation, scopeKey: c.scopeKey,
  })
}

/**
 * Create-or-update a case (the only write path). On first reply to a source
 * this mints the scope (opaque d, fresh key), grants it to the source's
 * ephemeral pubkey, and records it in the docket. Afterwards, updates are
 * free republishes under the same key.
 *
 * `sourceMsgs` is the recipient's full unwrapped thread ([{at, text}]) — the
 * case payload carries the *merged* dialogue, so the returning source reads
 * everything from one dereference. Recipient-side messages persist inside the
 * previous payload; `replyText`, if given, appends one more. `status` flips
 * open/archived (mirrored payload AND docket). `powPolicy` rides in the
 * payload so the source mines replies at the recipient's price.
 */
export async function upsertCase(relay, intakeSk, docket, src,
                                 { sourceMsgs = [], replyText, status, powPolicy = 20 }) {
  const intakePub = getPublicKey(intakeSk)
  let c = docket.cases.get(src)
  const isNew = !c
  if (isNew) c = {
    scopeId: opaqueId(), scopeName: 'case', generation: 1,
    scopeKey: newScopeKey(), status: 'open',
  }
  const statusChanged = Boolean(status) && status !== c.status
  if (status) c.status = status

  const prev = isNew ? null : await fetchCase(relay, intakePub, c)
  const kept = prev?.status === 'ok' ? prev.data : { messages: [], docs: [] }
  const seen = new Set(sourceMsgs.map(m => `${m.at}\x00${m.text}`))
  const messages = [
    ...sourceMsgs.map(m => ({ from: 'source', at: m.at, text: m.text })),
    // keep recipient messages, and any source messages the payload has that
    // the live thread doesn't (relays age out wraps before scopes)
    ...(kept.messages ?? []).filter(m =>
      m.from === 'recipient' || !seen.has(`${m.at}\x00${m.text}`)),
    ...(replyText ? [{ from: 'recipient', at: Math.floor(Date.now() / 1000), text: replyText }] : []),
  ].sort((a, b) => a.at - b.at)

  const payload = { status: c.status, messages, docs: kept.docs ?? [], pow: powPolicy }
  await publishScope(relay, intakeSk, {
    scopeId: c.scopeId, generation: c.generation, scopeKey: c.scopeKey, payload,
  })
  if (isNew) {
    await grant(relay, intakeSk, src, {
      scopeId: c.scopeId, generation: c.generation, scopeKey: c.scopeKey, scopeName: c.scopeName,
    })
    docket.cases.set(src, c)
  }
  if (isNew || statusChanged) await saveDocket(relay, intakeSk, docket)
  return { case: c, payload, isNew }
}

/** True when the live thread holds a source message the case payload lacks. */
export function caseOutOfSync(caseData, threadMsgs) {
  const have = new Set((caseData?.messages ?? [])
    .filter(m => m.from === 'source').map(m => `${m.at}\x00${m.text}`))
  return (threadMsgs ?? []).some(m => !have.has(`${m.at}\x00${m.text}`))
}
