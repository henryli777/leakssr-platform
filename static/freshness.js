(function (root) {
  'use strict';
  function timestamp(value) {
    const text = String(value || '').replace(/ UTC$/, '').replace(' ', 'T');
    return text ? Date.parse(/Z$|[+-]\d\d:\d\d$/.test(text) ? text : text + 'Z') : NaN;
  }
  function snapshotState(health, now = Date.now()) {
    if (health.stale === true) return 'stale';
    if (health.refresh_status === 'failed') return 'failed';
    if (health.sample_data === true || health.dataset_type === 'sample' || health.data_status === 'sample') return 'sample';
    const date = timestamp(health.build_time_utc);
    if (!Number.isFinite(date) || date > now + 300000) return 'unknown';
    const interval = Number.isFinite(health.refresh_interval_seconds) && health.refresh_interval_seconds > 0 ? health.refresh_interval_seconds : 1800;
    return now - date > (interval * 2 + (health.schedule_jitter_seconds || 0)) * 1000 ? 'historical' : 'current';
  }
  function snapshotKey(health) {
    return JSON.stringify([health.build_time_utc, health.last_attempt_utc, health.refresh_status, health.stale, health.validation?.checked_at]);
  }
  async function fetchData(url, { type = 'json', fetcher = root.fetch.bind(root), timeoutMs = 20000 } = {}) {
    const controller = new AbortController();
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => { reject(new Error('Data request timed out')); controller.abort(); }, timeoutMs);
    });
    try {
      return await Promise.race([deadline, (async () => {
        const response = await fetcher(url, { cache: 'no-cache', signal: controller.signal });
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return type === 'text' ? response.text() : response.json();
      })()]);
    } finally { clearTimeout(timer); }
  }
  async function readSnapshot(readHealth, readData, cached) {
    for (let attempt = 0; attempt < 3; attempt++) {
      const health = await readHealth();
      if (cached && snapshotKey(health) === snapshotKey(cached.health)) return { health, data: cached.data };
      const data = await readData();
      const after = await readHealth();
      if (snapshotKey(health) === snapshotKey(after)) return { health: after, data };
    }
    throw new Error('Snapshot changed during refresh');
  }
  function createIndexCache(load) {
    let pending;
    return {
      read() {
        if (!pending) {
          const owner = Promise.resolve().then(load).catch((error) => { if (pending === owner) pending = undefined; throw error; });
          pending = owner;
        }
        return pending;
      },
      invalidate() { pending = undefined; },
    };
  }
  function createPoller({ load, isVisible, intervalMs = 60000, setTimer = setTimeout, clearTimer = clearTimeout, onError = () => {} }) {
    let running = false, timer = null, pending;
    function clear() { if (timer !== null) clearTimer(timer); timer = null; }
    function refresh() {
      clear();
      if (!running || !isVisible()) return Promise.resolve();
      if (pending) return pending;
      pending = Promise.resolve().then(load).catch(onError).finally(() => {
        pending = undefined;
        if (running && isVisible()) timer = setTimer(refresh, intervalMs);
      });
      return pending;
    }
    return {
      start() { running = true; return refresh(); },
      refresh,
      stop() { running = false; clear(); },
    };
  }
  function watch(document, load) {
    const poller = createPoller({ load, isVisible: () => !document.hidden });
    document.addEventListener('visibilitychange', poller.refresh);
    root.addEventListener('focus', poller.refresh);
    root.addEventListener('online', poller.refresh);
    root.addEventListener('pageshow', poller.start);
    root.addEventListener('pagehide', poller.stop);
    poller.start();
    return poller;
  }
  const api = { timestamp, snapshotState, snapshotKey, fetchData, readSnapshot, createIndexCache, createPoller, watch };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.LeakSSRFreshness = api;
})(typeof window !== 'undefined' ? window : globalThis);
