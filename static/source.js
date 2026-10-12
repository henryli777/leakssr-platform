(function (root) {
  'use strict';
  const SOURCE_ID = /^[a-f0-9]{12}$/;
  const CHANNELS = { google: 'Google', github: 'GitHub', telegram: 'Telegram' };
  const PROTOCOLS = { ss: 'Shadowsocks', ssr: 'ShadowsocksR', vmess: 'VMess', vless: 'VLESS', trojan: 'Trojan', hysteria2: 'Hysteria2' };

  function safeHttpUrl(value) {
    if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return null;
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && url.hostname ? url.href : null;
    } catch (_) { return null; }
  }

  function number(value) { return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null; }

  async function initialize(document) {
    const get = (id) => document.getElementById(id);
    const id = new URLSearchParams(root.location.search).get('id');
    let timer;
    const format = (value) => number(value) === null ? '—' : new Intl.NumberFormat('zh-CN', { maximumFractionDigits: 2 }).format(value);

    function icons() { if (root.lucide && root.lucide.createIcons) root.lucide.createIcons({ attrs: { 'stroke-width': 1.7 } }); }
    function element(tag, className, text) { const item = document.createElement(tag); if (className) item.className = className; if (text !== undefined) item.textContent = String(text); return item; }
    function error(title, text) {
      get('source-title').textContent = title;
      get('source-error').hidden = false;
      get('source-error-title').textContent = title;
      get('source-error-copy').textContent = text;
    }
    function notice(text) { get('source-notice').hidden = false; get('source-notice-text').textContent = text; }
    function toast(text) { root.clearTimeout(timer); get('toast').textContent = text; get('toast').hidden = false; timer = root.setTimeout(() => { get('toast').hidden = true; }, 2200); }
    async function copy(text) {
      try {
        if (root.navigator.clipboard && root.isSecureContext) await root.navigator.clipboard.writeText(text);
        else { const field = element('textarea', 'copy-field'); field.value = text; document.body.append(field); field.select(); const copied = document.execCommand('copy'); field.remove(); if (!copied) throw new Error('Copy failed'); }
        toast('已复制');
      } catch (_) { toast('复制失败，请选择内容后复制'); }
    }
    async function fetchData(path, type) {
      const response = await root.fetch(new URL(path, document.baseURI), { cache: 'no-cache' });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return type === 'text' ? response.text() : response.json();
    }
    icons();
    if (!SOURCE_ID.test(id || '')) { error('来源 ID 无效', '来源 ID 应为 12 位十六进制字符。请从来源清单重新打开详情。'); return; }
    const results = await Promise.allSettled([
      fetchData('sub/providers/' + id + '.json'),
      fetchData('sub/providers/' + id + '.txt', 'text'),
      fetchData('sub/url_meta.json'),
    ]);
    const [metadata, nodes, manifest] = results;
    const manifestRow = manifest.status === 'fulfilled' && Array.isArray(manifest.value) ? manifest.value.find((item) => item && typeof item === 'object' && item.id === id) : null;
    const provider = metadata.status === 'fulfilled' && metadata.value && typeof metadata.value === 'object' && !Array.isArray(metadata.value) ? metadata.value : null;
    const meta = provider ? { ...(manifestRow || {}), ...provider } : manifestRow;
    if (!meta) { error('来源详情暂不可用', '该来源未生成详情记录，或来源已从本次构建中移除。'); return; }
    const name = typeof meta.provider === 'string' && meta.provider ? meta.provider : typeof meta.host === 'string' && meta.host ? meta.host : '来源 ' + id;
    get('source-title').textContent = name;
    document.title = name + ' · LeakSSR';
    get('source-detail').hidden = false;
    get('source-id').textContent = id;
    get('source-node-total').textContent = format(meta.nodes_total);
    const latency = get('source-latency');
    latency.textContent = number(meta.response_ms) === null ? '—' : format(Math.round(meta.response_ms));
    if (number(meta.response_ms) !== null) latency.append(element('span', '', 'ms'));
    const traffic = meta.traffic && typeof meta.traffic === 'object' ? meta.traffic : {};
    const unit = typeof traffic.unit === 'string' && /^[A-Za-z]{1,5}$/.test(traffic.unit) ? traffic.unit : 'GB';
    [['source-remaining', traffic.remaining], ['source-capacity', traffic.total]].forEach(([key, value]) => { get(key).textContent = format(value); if (number(value) !== null) get(key).append(element('span', '', unit)); });
    const url = safeHttpUrl(meta.url);
    get('source-original-url').replaceChildren();
    const address = element(url ? 'a' : 'span', '', meta.url || '未提供订阅 URL');
    if (url) { address.href = url; address.target = '_blank'; address.rel = 'noopener noreferrer'; get('copy-source-url').disabled = false; get('copy-source-url').addEventListener('click', () => copy(meta.url)); }
    get('source-original-url').append(address);
    const available = typeof manifestRow?.available === 'boolean' ? manifestRow.available : typeof meta.available === 'boolean' ? meta.available : null;
    get('source-badge').append(element('span', 'badge ' + (available === true ? 'available' : available === false ? 'unavailable' : 'unknown'), available === true ? '构建时可用' : available === false ? '本次构建不可用' : '可用状态未记录'));
    get('source-updated').textContent = typeof meta.updated_at === 'string' && meta.updated_at ? meta.updated_at + ' UTC' : '未记录';
    get('source-channel').textContent = CHANNELS[meta.source] || '未记录';
    get('source-first-seen').textContent = typeof meta.first_seen === 'string' ? meta.first_seen : '未记录';
    const counts = meta.protocol_counts && typeof meta.protocol_counts === 'object' && !Array.isArray(meta.protocol_counts) ? meta.protocol_counts : {};
    const validProtocols = Object.entries(counts).filter(([key, value]) => Object.hasOwn(PROTOCOLS, key) && number(value) !== null && value > 0);
    get('source-protocols').replaceChildren();
    validProtocols.forEach(([key, value]) => get('source-protocols').append(element('span', 'badge protocol', PROTOCOLS[key] + ' · ' + format(value))));
    if (!validProtocols.length) get('source-protocols').textContent = '未记录';
    if (nodes.status === 'fulfilled') {
      const content = nodes.value;
      get('source-nodes').value = content;
      const lines = content.split(/\r?\n/).filter((line) => line.trim()).length;
      get('source-node-line-count').textContent = lines + ' 条记录';
      get('copy-source-nodes').disabled = !content.trim();
      get('copy-source-nodes').addEventListener('click', () => copy(content));
      get('download-source').hidden = false;
      get('download-source').href = 'sub/providers/' + id + '.txt';
      get('download-source').download = 'leakssr-source-' + id + '.txt';
      if (!content.trim()) notice('该来源的本次构建节点记录为空。');
    } else { get('source-nodes').value = ''; get('source-node-line-count').textContent = '未生成节点记录'; notice('来源元数据已载入，原始节点文件暂不可用。'); }
    if (metadata.status === 'rejected') notice('当前展示来源清单中的记录，独立详情文件暂不可用。');
    if (typeof meta.updated_at === 'string') {
      const stamp = Date.parse(/Z$|[+-]\d\d:\d\d$/.test(meta.updated_at) ? meta.updated_at : meta.updated_at.replace(' ', 'T') + 'Z');
      if (Number.isFinite(stamp) && Date.now() - stamp > 48 * 3600000) notice('该来源记录已超过 48 小时，节点与可用状态来自历史构建。');
    }
    icons();
  }
  if (typeof module !== 'undefined' && module.exports) module.exports = { safeHttpUrl, number, SOURCE_ID };
  if (root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', () => initialize(root.document));
    else initialize(root.document);
  }
})(typeof window !== 'undefined' ? window : globalThis);
