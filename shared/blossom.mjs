// blossom.mjs — encrypted attachment transport over public Blossom servers
// (BUD-01/02), adapted from Nvelope's live-proven pipeline (separate apps,
// separate copies). The pipeline: pad → encrypt under a random per-file key →
// upload ciphertext (mirrored, kind-24242 auth) → fetch from any mirror →
// verify sha256 of the ciphertext → decrypt → unpad. Servers hold ciphertext
// whose size reveals only the padding class; the per-file key travels INSIDE
// the encrypted rumor (tips, replies) or case payload (`docs`), never near a
// server or relay in the clear.
//
// Cipher note: NIP-44 v2 hard-caps plaintext at 64 KiB — files can't ride
// it directly. We use XChaCha20-Poly1305 from audited @noble/ciphers (the
// same family NIP-44 builds on) with the 32-byte filekey used directly, no
// ECDH — the exact trust construction of NIP-DA scope keys.

import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { pad, unpad } from './pad.mjs'

// Public servers verified live (2026-07-10, Nvelope's blossom-probe) to take
// anonymous ciphertext uploads at 50 MB+ with working BUD-02 delete.
export const DEFAULT_SERVERS = ['https://nostr.download', 'https://cdn.hzrd149.com']

// Client-side cap. Sober messaging beats a mid-upload 413 from a stranger's
// server; verified servers take 50 MB+, so the practical bound is theirs.
export const MAX_FILE_BYTES = 100 * 1024 * 1024

export const newFileKey = () => crypto.getRandomValues(new Uint8Array(32))

const hex = (b) => Array.from(b, x => x.toString(16).padStart(2, '0')).join('')
const unhex = (s) => Uint8Array.from(s.match(/../g), h => parseInt(h, 16))

export async function sha256hex(bytes) {
  const d = await crypto.subtle.digest('SHA-256', bytes)
  return hex(new Uint8Array(d))
}

/** Pad + encrypt: returns nonce‖ciphertext, sized by padding class alone. */
export function encryptBlob(filekey, bytes) {
  const nonce = crypto.getRandomValues(new Uint8Array(24))
  const cipher = xchacha20poly1305(filekey, nonce).encrypt(pad(bytes))
  const out = new Uint8Array(24 + cipher.length)
  out.set(nonce)
  out.set(cipher, 24)
  return out
}

/** Decrypt + unpad; throws on any tampering (Poly1305 tag). */
export function decryptBlob(filekey, blob) {
  return unpad(xchacha20poly1305(filekey, blob.slice(0, 24)).decrypt(blob.slice(24)))
}

// --- the attachment manifest entry (spec §5) ---------------------------------
// { name, size_padded, mime, sha256_cipher, servers, filekey } — carried only
// inside encrypted payloads. Everything a peer needs to fetch, verify, decrypt.

/**
 * Encrypt + upload one file; returns the manifest entry to embed in a rumor's
 * `files` array or a case payload's `docs` array. Enforces MAX_FILE_BYTES
 * before touching the network.
 */
export async function attachFile(servers, signer, { name, mime, bytes }) {
  if (bytes.length > MAX_FILE_BYTES) throw new Error(
    `“${name}” is ${(bytes.length / 1048576).toFixed(1)} MB — the limit is 100 MB per file`)
  const filekey = newFileKey()
  const cipher = encryptBlob(filekey, bytes)
  const desc = await uploadBlob(servers, signer, cipher)
  return { name, size_padded: cipher.length, mime, sha256_cipher: desc.sha256,
           servers: desc.servers, filekey: hex(filekey) }
}

/** Fetch → hash-verify (inside fetchBlob) → decrypt one manifest entry. */
export async function fetchAttachment(entry) {
  return decryptBlob(unhex(entry.filekey), await fetchBlob(entry.servers, entry.sha256_cipher))
}

/** Shape check for entries arriving in hostile input (rumors, payloads). */
export const validAttachment = (e) => Boolean(e) && typeof e.name === 'string'
  && /^[0-9a-f]{64}$/.test(e.sha256_cipher ?? '') && /^[0-9a-f]{64}$/.test(e.filekey ?? '')
  && Array.isArray(e.servers) && e.servers.length > 0
  && e.servers.every(s => typeof s === 'string' && /^https?:\/\//.test(s))

// --- BUD-01/02 HTTP, via the NIP-DA signer interface -------------------------

const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)))

async function authHeader(signer, verb, sha256) {
  const event = await signer.signEvent({
    kind: 24242,
    created_at: Math.floor(Date.now() / 1000),
    tags: [['t', verb], ['x', sha256],
      ['expiration', String(Math.floor(Date.now() / 1000) + 600)]],
    content: `${verb} blob`,
  })
  return 'Nostr ' + b64(JSON.stringify(event))
}

const url = (server, path) => new URL(path, server.endsWith('/') ? server : server + '/').href

/**
 * Upload ciphertext to every server (mirroring); ≥1 success is success,
 * like the relay publish contract. Per-server retries with backoff — but a
 * 4xx is a verdict, not weather, and fails that server immediately.
 * Returns { sha256, size, servers, failures }.
 */
export async function uploadBlob(servers, signer, cipher,
  { retries = 2, timeout = 120_000, fetchImpl = fetch } = {}) {
  const sha256 = await sha256hex(cipher)
  const auth = await authHeader(signer, 'upload', sha256)
  const results = await Promise.allSettled(servers.map(async (server) => {
    for (let attempt = 0; ; attempt++) {
      try {
        const res = await fetchImpl(url(server, 'upload'), {
          method: 'PUT', body: cipher,
          headers: { authorization: auth, 'content-type': 'application/octet-stream' },
          signal: AbortSignal.timeout(timeout),
        })
        if (!res.ok) {
          const err = new Error(`HTTP ${res.status} ${(await res.text()).slice(0, 80)}`.trim())
          err.status = res.status
          throw err
        }
        return server
      } catch (err) {
        if ((err.status >= 400 && err.status < 500) || attempt >= retries) throw err
        await new Promise(r => setTimeout(r, 500 * (attempt + 1)))
      }
    }
  }))
  const ok = results.filter(r => r.status === 'fulfilled').map(r => r.value)
  const failures = results.map((r, i) => r.status === 'rejected'
    ? { server: servers[i], status: r.reason?.status, message: String(r.reason?.message ?? r.reason).slice(0, 120) }
    : null).filter(Boolean)
  if (!ok.length) throw new Error('no server accepted the blob: ' +
    failures.map(f => `${f.server}: ${f.message}`).join(' | '))
  return { sha256, size: cipher.length, servers: ok, failures }
}

/**
 * Fetch ciphertext by hash, trying servers in order. A blob whose bytes
 * don't hash to `sha256` is a lying server — skipped, never returned.
 */
export async function fetchBlob(servers, sha256, { timeout = 120_000, fetchImpl = fetch } = {}) {
  const errors = []
  for (const server of servers) {
    try {
      const res = await fetchImpl(url(server, sha256), { signal: AbortSignal.timeout(timeout) })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const bytes = new Uint8Array(await res.arrayBuffer())
      if (await sha256hex(bytes) !== sha256) throw new Error('hash mismatch — server returned wrong bytes')
      return bytes
    } catch (err) { errors.push(`${server}: ${err.message}`) }
  }
  throw new Error(`blob ${sha256.slice(0, 12)}… unavailable: ${errors.join(' | ')}`)
}

/** BUD-02 delete on every server; best-effort, returns how many confirmed. */
export async function deleteBlob(servers, signer, sha256, { timeout = 30_000, fetchImpl = fetch } = {}) {
  const auth = await authHeader(signer, 'delete', sha256)
  const results = await Promise.allSettled(servers.map(async (server) => {
    const res = await fetchImpl(url(server, sha256), {
      method: 'DELETE', headers: { authorization: auth },
      signal: AbortSignal.timeout(timeout),
    })
    if (!res.ok) throw new Error(`HTTP ${res.status}`)
  }))
  return results.filter(r => r.status === 'fulfilled').length
}
