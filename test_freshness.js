const assert = require('node:assert/strict');
const test = require('node:test');
const platform = require('./static/platform.js');
let fresh = {};
try { fresh = require('./static/freshness.js'); } catch (error) { if (error.code !== 'MODULE_NOT_FOUND') throw error; }

test('freshness follows the 30 minute cadence with a run-time grace, not 48 hours', () => {
  const health = { build_time_utc: '2026-10-15 00:00:00 UTC', refresh_interval_seconds: 1800 };
  assert.equal(platform.snapshotState(health, Date.parse('2026-10-15T00:45:00Z')), 'current');
  assert.equal(platform.snapshotState(health, Date.parse('2026-10-15T01:01:00Z')), 'historical');
  assert.equal(platform.snapshotState({}, Date.now()), 'unknown');
  assert.equal(platform.snapshotState({ build_time_utc: 'invalid' }), 'unknown');
  assert.equal(platform.snapshotState(health, Date.parse('2026-10-14T23:00:00Z')), 'unknown');
});

test('visible polling coalesces requests, pauses hidden, and retries after failures', async () => {
  assert.equal(typeof fresh.createPoller, 'function');
  let visible = true, calls = 0, finish;
  const timers = new Map(); let seq = 0;
  const poller = fresh.createPoller({
    load: () => { calls++; return new Promise((resolve) => { finish = resolve; }); },
    isVisible: () => visible,
    setTimer: (fn, delay) => { assert.equal(delay, 60000); timers.set(++seq, fn); return seq; },
    clearTimer: (id) => timers.delete(id),
  });
  const initial = poller.start();
  await Promise.resolve();
  poller.refresh(); poller.refresh();
  assert.equal(calls, 1);
  finish(); await initial;
  assert.equal(timers.size, 1);
  visible = false; await poller.refresh();
  assert.equal(timers.size, 0); assert.equal(calls, 1);
  visible = true; const returned = poller.refresh();
  await Promise.resolve(); assert.equal(calls, 2);
  finish(); await returned;
  poller.stop(); assert.equal(timers.size, 0);
});

test('snapshot read retries a pointer switch rather than mixing old health and new data', async () => {
  assert.equal(typeof fresh.readSnapshot, 'function');
  const health = [{ build_time_utc: 'A' }, { build_time_utc: 'B' }, { build_time_utc: 'B' }, { build_time_utc: 'B' }];
  let reads = 0;
  const result = await fresh.readSnapshot(async () => health.shift(), async () => ++reads);
  assert.equal(result.health.build_time_utc, 'B'); assert.equal(result.data, 2);
  let serial = 0;
  await assert.rejects(fresh.readSnapshot(async () => ({ build_time_utc: String(++serial) }), async () => 1), /changed/);
});

test('poll failures keep polling and cached snapshots skip unchanged large payloads', async () => {
  let failures = 0, timer;
  const poller = fresh.createPoller({ load: async () => { throw new Error('offline'); }, isVisible: () => true,
    setTimer: (fn) => { timer = fn; return 1; }, clearTimer: () => {}, onError: () => { failures++; } });
  await poller.start(); assert.equal(failures, 1); assert.equal(typeof timer, 'function');
  await timer(); assert.equal(failures, 2); poller.stop();
  const health = { build_time_utc: 'unchanged' };
  const cached = { health, data: ['cached'] };
  assert.deepEqual(await fresh.readSnapshot(async () => health, () => { throw new Error('must not fetch'); }, cached), cached);
  assert.notEqual(fresh.snapshotKey(health), fresh.snapshotKey({ ...health, last_attempt_utc: 'failed-later' }));
});

test('index invalidation prevents failed old requests from discarding the new cache', async () => {
  assert.equal(typeof fresh.createIndexCache, 'function');
  let calls = 0, fail;
  const cache = fresh.createIndexCache(() => ++calls === 1 ? new Promise((_, reject) => { fail = reject; }) : Promise.resolve('new'));
  const old = cache.read(); await Promise.resolve();
  cache.invalidate(); const current = cache.read();
  assert.equal(await current, 'new'); fail(new Error('old'));
  await assert.rejects(old, /old/);
  assert.equal(await cache.read(), 'new'); assert.equal(calls, 2);
});

test('data requests have a deadline including a stalled response body', async () => {
  assert.equal(typeof fresh.fetchData, 'function');
  let signal;
  const fetcher = async (_url, options) => {
    signal = options.signal;
    return { ok: true, json: () => new Promise(() => {}) };
  };
  await assert.rejects(fresh.fetchData('/fixture', { fetcher, timeoutMs: 5 }), /timed out/);
  assert.equal(signal.aborted, true);
  assert.deepEqual(await fresh.fetchData('/fixture', {
    fetcher: async () => ({ ok: true, json: async () => ({ value: 1 }) }), timeoutMs: 100,
  }), { value: 1 });
});
