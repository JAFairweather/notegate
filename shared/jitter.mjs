// jitter.mjs — timing-correlation resistance for source-side publishes
// (spec §6: randomized publish delays and per-relay jitter on every
// source-side publish).
//
// A source that hands the same wrap to three relays in the same instant
// gives a network observer a correlation signature: three simultaneous
// arrivals, one origin. Staggering each relay's copy by an INDEPENDENT
// random delay (default 0–90 s) blurs that edge. This is mitigation, not
// elimination — SECURITY.md and the submit page both say so.
//
// `relays` is an array of publish-capable objects, ONE PER RELAY URL (the
// submit page builds one single-URL LiveRelay per relay; tests pass
// in-memory relays). The protocol lib is untouched — this is a wrapper.

export const MAX_JITTER_MS = 90_000

// Test hook: suites and the browser E2E harness set this global so runs
// stay fast. Shipped pages never set it; absent, the full window applies.
export const currentMaxJitterMs = () =>
  globalThis.NOTEGATE_MAX_JITTER_MS ?? MAX_JITTER_MS

/**
 * Publish `event` to every relay, each on its own uniform random delay in
 * [0, maxMs). Resolves when every relay has been attempted; succeeds when
 * at least one accepted (the same ≥1-ack contract as LiveRelay.publish).
 * `onProgress(done, of)` fires after each successful relay.
 * Returns { acks, of, delays } — delays exposed for tests.
 */
export async function publishJittered(relays, event,
    { maxMs = currentMaxJitterMs(), onProgress } = {}) {
  const delays = relays.map(() => Math.random() * maxMs)
  let done = 0
  const results = await Promise.allSettled(relays.map(async (relay, i) => {
    await new Promise(r => setTimeout(r, delays[i]))
    const receipt = await relay.publish(event)
    onProgress?.(++done, relays.length)
    return receipt
  }))
  const acks = results.filter(r => r.status === 'fulfilled').length
  if (acks === 0) throw new Error('no relay accepted the event: ' + results
    .map(r => String(r.reason?.message ?? r.reason).slice(0, 60)).join(' | '))
  return { acks, of: relays.length, delays }
}
