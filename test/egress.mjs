// egress.mjs — the zero-egress guarantee (spec §6: "the submit page must
// make zero network requests except to relays and Blossom servers"),
// enforced at the strongest level feasible without a headless browser:
//
//   1. STATIC SCAN: every absolute URL in shipped code (root redirect,
//      submit/, inbox/, shared/, lib/) must resolve to an allowed origin.
//      Network origins are exactly the configured relays, the default
//      Blossom hosts, and esm.sh (pinned module CDN). github.com is allowed
//      ONLY as an <a href> in HTML (user-initiated navigation, not egress);
//      w3.org is allowed ONLY as an SVG namespace identifier (never
//      fetched); localhost/URL-parse bases are allowed ONLY in the dev
//      server.
//   2. CONSISTENCY: the allowlist is cross-checked against the live code —
//      the relay lists in submit.mjs and inbox.mjs, DEFAULT_SERVERS
//      (imported from shipped code), and both pages' import maps must be
//      subsets of it, so the list can't drift.
//   3. IMPORT-TIME INTERCEPTION: fetch / WebSocket / XMLHttpRequest are
//      replaced with recording traps, then every DOM-free module is
//      imported; zero network calls may occur at module load. Nothing
//      phones home just by being loaded.
//   4. AT-REST DISCIPLINE (spec §6 memory hygiene): the submit page touches
//      no storage at all; the inbox persists exactly the NIP-49 ncryptsec
//      (localStorage), the archive triage list (ephemeral pubkeys, never
//      key material), and the tab-session login slot (sessionStorage).
//
// What this does NOT cover (documented, not hidden): runtime calls in a
// real browser (nostr-tools opens sockets only to the relay URLs we pass
// it — the static scan pins those), and a tampered CDN serving different
// code than audited (see SECURITY.md, "code delivery").
//
//   node test/egress.mjs

import { readFileSync, readdirSync } from 'node:fs'
import { join, dirname } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = join(dirname(fileURLToPath(import.meta.url)), '..')

let passed = 0, failed = 0
const check = (name, ok, detail = '') => {
  console.log(`  ${ok ? '\x1b[32mPASS\x1b[0m' : '\x1b[31mFAIL\x1b[0m'}  ${name}${detail ? ` — ${detail}` : ''}`)
  ok ? passed++ : failed++
}

// The one and only egress allowlist.
const NETWORK = new Set([
  'wss://relay.damus.io', 'wss://nos.lol', 'wss://relay.primal.net',  // relays
  'https://nostr.download', 'https://cdn.hzrd149.com',                // Blossom
  'https://esm.sh',                                                   // pinned modules
])
const LINK_ONLY = new Set(['https://github.com'])       // <a href> in HTML only
const NAMESPACE = new Set(['http://www.w3.org'])        // svg xmlns, never fetched
const DEV_ONLY = new Set(['http://localhost:4442', 'http://x'])  // serve.mjs

console.log('\n1. Static scan: every URL in shipped code resolves to an allowed origin')
const dirs = ['submit', 'inbox', 'shared', 'lib']
const files = [
  join(root, 'index.html'),
  ...dirs.flatMap(d => readdirSync(join(root, d))
    .filter(f => /\.(mjs|html)$/.test(f)).map(f => join(root, d, f))),
]
const urlRx = /\b(?:https?|wss?):\/\/[^\s"'`<>\\)\]{},]*/g
const offenders = []
let scanned = 0, found = 0
for (const file of files) {
  const src = readFileSync(file, 'utf8')
  scanned++
  for (const raw of src.match(urlRx) ?? []) {
    let origin, host
    try { ({ origin, host } = new URL(raw)) } catch { origin = raw; host = '' }
    if (!host) continue                       // bare "wss://" in prose, not a destination
    found++
    const rel = file.slice(root.length + 1)
    if (NETWORK.has(origin)) continue
    if (LINK_ONLY.has(origin) && rel.endsWith('.html')
        && new RegExp(`href="${origin}[^"]*"`).test(src)) continue
    if (NAMESPACE.has(origin) && src.includes(`xmlns='${origin}`)) continue
    if (DEV_ONLY.has(origin) && rel === 'inbox/serve.mjs') continue
    offenders.push(`${rel}: ${raw}`)
  }
}
check(`no unexpected origins in ${scanned} files (${found} URLs found)`,
  offenders.length === 0, offenders.join(' | '))
check('the scan itself sees the expected surface', found >= 12,
  'regex or file list broke if this number collapses')

console.log('\n2. Consistency: the allowlist matches the live code')
for (const page of ['submit/submit.mjs', 'inbox/inbox.mjs']) {
  const relays = readFileSync(join(root, page), 'utf8').match(/wss:\/\/[a-z0-9.-]+/g) ?? []
  check(`${page} relays are allowlisted`, relays.length >= 3
    && relays.every(r => NETWORK.has(r)), [...new Set(relays)].join(', '))
}
for (const page of ['submit/index.html', 'inbox/index.html']) {
  const htmlSrc = readFileSync(join(root, page), 'utf8')
  const importMap = htmlSrc.match(/<script type="importmap">([\s\S]*?)<\/script>/)?.[1] ?? ''
  const imports = Object.values(JSON.parse(importMap).imports).map(u => new URL(u).origin)
  check(`${page} import map points only at esm.sh`, imports.length >= 3
    && imports.every(o => o === 'https://esm.sh'), [...new Set(imports)].join(', '))
}

console.log('\n3. Import-time interception: nothing phones home on module load')
const calls = []
globalThis.fetch = (u) => { calls.push(String(u)); return Promise.reject(new Error('egress blocked')) }
globalThis.XMLHttpRequest = class { open(m, u) { calls.push(String(u)) } send() { throw new Error('egress blocked') } setRequestHeader() {} }
globalThis.WebSocket = class { constructor(u) { calls.push(String(u)); throw new Error('egress blocked') } }
const modules = ['../shared/pad.mjs', '../shared/pow.mjs', '../shared/wrap.mjs',
  '../shared/blossom.mjs', '../shared/jitter.mjs', '../inbox/case.mjs',
  '../inbox/rotate.mjs', '../lib/nipxx.mjs', '../lib/liverelay.mjs', '../lib/relay.mjs']
let importErr = null
let blossom
try {
  for (const m of modules) {
    const mod = await import(m)
    if (m.includes('blossom')) blossom = mod
  }
} catch (err) { importErr = err }
check('all shipped modules import cleanly under the traps', importErr === null, importErr?.message ?? '')
check('zero network calls at import time', calls.length === 0, calls.join(', '))
check('DEFAULT_SERVERS are allowlisted',
  blossom.DEFAULT_SERVERS.length >= 2 && blossom.DEFAULT_SERVERS.every(s => NETWORK.has(new URL(s).origin)),
  blossom.DEFAULT_SERVERS.join(', '))

console.log('\n4. At-rest discipline: what the pages may persist, and nothing else')
const submitSrc = readFileSync(join(root, 'submit', 'submit.mjs'), 'utf8')
  + readFileSync(join(root, 'submit', 'index.html'), 'utf8')
check('the submit page never touches localStorage or sessionStorage',
  !/localStorage|sessionStorage/.test(submitSrc))
const inboxSrc = ['inbox.mjs', 'case.mjs', 'rotate.mjs']
  .map(f => readFileSync(join(root, 'inbox', f), 'utf8')).join('\n')
const lsWrites = inboxSrc.match(/localStorage\.setItem\([^\n]*/g) ?? []
check('inbox localStorage writes are exactly ncryptsec + archive triage',
  lsWrites.length === 2
  && lsWrites.some(w => w.includes('NC_KEY') && w.includes('nip49.encrypt'))
  && lsWrites.some(w => w.includes('archiveKey()')), lsWrites.join(' | '))
check('key material reaches localStorage only through nip49.encrypt',
  lsWrites.every(w => !/nsec|hexOf|\bsk\b/.test(w) || w.includes('nip49.encrypt')))
const ssWrites = inboxSrc.match(/sessionStorage\.setItem\('([^']+)'/g) ?? []
check('sessionStorage keys are exactly the tab-session login + protect opt-out',
  ssWrites.length === 2 && ssWrites.join().includes('notegate-login')
  && ssWrites.join().includes('notegate-no-protect'), ssWrites.join(' | '))

console.log(`\n${failed === 0 ? '\x1b[32m' : '\x1b[31m'}${passed} passed, ${failed} failed\x1b[0m`)
process.exit(failed === 0 ? 0 : 1)
