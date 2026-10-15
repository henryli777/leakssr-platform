(function (root) {
  'use strict';

  const PAGE_SIZE = 20;
  const URI_QUERY = /^[a-z][a-z0-9+.-]*:\/\//i;
  const NODE_PREFIX = /^(?:vmess|vless|trojan|ss|ssr|hy2|hysteria2):/i;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  function stableValue(value) {
    if (Array.isArray(value)) return value.map(stableValue);
    if (value && typeof value === 'object') {
      const sorted = {};
      Object.keys(value).sort().forEach((key) => { sorted[key] = stableValue(value[key]); });
      return sorted;
    }
    return value;
  }

  function decodeBase64(value) {
    const input = decodeURIComponent(value).replace(/-/g, '+').replace(/_/g, '/');
    if (!input || !/^[A-Za-z0-9+/]*={0,2}$/.test(input) || input.length % 4 === 1) throw new Error('Invalid Base64');
    const padded = input.replace(/=+$/, '') + '='.repeat((4 - input.replace(/=+$/, '').length % 4) % 4);
    const binary = typeof atob === 'function' ? atob(padded) : Buffer.from(padded, 'base64').toString('binary');
    return new TextDecoder('utf-8', { fatal: true }).decode(Uint8Array.from(binary, (char) => char.charCodeAt(0)));
  }

  function normalizeServer(server) {
    const host = String(server || '').replace(/^\[|\]$/g, '').replace(/\.+$/, '').toLowerCase();
    if (!host || /[\s/@?#]/.test(host)) throw new Error('Invalid server');
    if (host.includes(':')) return new URL('http://[' + host + ']').hostname.slice(1, -1);
    if (/[^\x00-\x7f]/.test(host)) {
      const dnsName = host.normalize('NFKC').replace(/\u00df/g, 'ss').replace(/\u03c2/g, '\u03c3').replace(/[\u200b-\u200d\u2060\ufeff]/g, '');
      return new URL('http://' + dnsName).hostname;
    }
    return host;
  }

  function normalizePort(value) {
    if (!/^\d+$/.test(String(value))) throw new Error('Invalid port');
    const port = Number(value);
    if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Invalid port');
    return port;
  }

  function queryParams(query, ssr) {
    const pairs = [];
    for (const [key, rawValue] of new URLSearchParams(query)) {
      if (ssr && (key === 'remarks' || key === 'group')) continue;
      const value = ssr && (key === 'obfsparam' || key === 'protoparam') && rawValue ? decodeBase64(rawValue) : rawValue;
      pairs.push([key, value]);
    }
    return pairs.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
  }

  function parseEndpoint(value, defaultPort) {
    const endpoint = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(value);
    if (!endpoint) throw new Error('Invalid endpoint');
    return { server: normalizeServer(endpoint[1]), port: normalizePort(endpoint[2] || defaultPort) };
  }

  function splitConnection(value) {
    const match = /^([^/?]+)([^?]*)(?:\?(.*))?$/.exec(value);
    if (!match) throw new Error('Invalid connection');
    const at = match[1].lastIndexOf('@');
    if (at < 1) throw new Error('Missing credentials');
    return {
      ...parseEndpoint(match[1].slice(at + 1), 443),
      credentials: decodeURIComponent(match[1].slice(0, at)),
      path: match[2] === '/' ? '' : match[2],
      params: queryParams(match[3] || '', false),
    };
  }

  function canonicalNodeKey(uri) {
    try {
      if (typeof uri !== 'string') return null;
      const input = uri.trim();
      const match = /^([a-z][a-z0-9+.-]*):\/\/([\s\S]+)$/i.exec(input);
      if (!match) return null;
      let protocol = match[1].toLowerCase();
      if (protocol === 'hy2') protocol = 'hysteria2';
      const body = match[2].split('#', 1)[0];
      if (!body || /\s/.test(body) || /%(?![0-9a-f]{2})/i.test(input)) return null;
      let key;
      if (protocol === 'vmess') {
        const config = JSON.parse(decodeBase64(body));
        if (!config || typeof config !== 'object' || Array.isArray(config) || typeof config.id !== 'string' || !config.id || typeof config.add !== 'string') return null;
        const server = normalizeServer(config.add);
        const port = normalizePort(config.port === undefined ? 443 : config.port);
        const normalized = { ...config };
        ['ps', 'v', 'add', 'port'].forEach((name) => { delete normalized[name]; });
        const aid = normalized.aid === undefined ? 0 : normalized.aid;
        if (!/^\d+$/.test(String(aid))) return null;
        normalized.aid = Number(aid);
        if (!Number.isSafeInteger(normalized.aid)) return null;
        for (const [name, fallback] of [['net', 'tcp'], ['scy', 'auto'], ['tls', '']]) {
          if (normalized[name] === undefined) normalized[name] = fallback;
        }
        if (UUID.test(normalized.id)) {
          normalized.id = normalized.id.toLowerCase();
        }
        key = { protocol, server, port, config: normalized };
      } else if (protocol === 'ssr') {
        const decoded = decodeBase64(body);
        const queryAt = decoded.indexOf('/?');
        const connection = (queryAt < 0 ? decoded : decoded.slice(0, queryAt)).replace(/\/$/, '');
        const fields = connection.split(':');
        if (fields.length < 6) return null;
        const [port, ssr_protocol, cipher, obfs, password] = fields.slice(-5);
        const decodedPassword = decodeBase64(password);
        if (!ssr_protocol || !cipher || !obfs || !decodedPassword) return null;
        key = {
          protocol, server: normalizeServer(fields.slice(0, -5).join(':')), port: normalizePort(port),
          ssr_protocol, cipher, obfs, password: decodedPassword,
          params: queryParams(queryAt < 0 ? '' : decoded.slice(queryAt + 2), true),
        };
      } else if (protocol === 'ss') {
        const queryAt = body.indexOf('?');
        let connection = queryAt < 0 ? body : body.slice(0, queryAt);
        connection = connection.replace(/\/$/, '');
        const legacy = !connection.includes('@');
        const params = queryParams(queryAt < 0 ? '' : body.slice(queryAt + 1), false);
        if (legacy) {
          connection = decodeBase64(connection);
          const innerQueryAt = connection.indexOf('?');
          if (innerQueryAt >= 0) {
            params.push(...queryParams(connection.slice(innerQueryAt + 1), false));
            connection = connection.slice(0, innerQueryAt);
            params.sort((a, b) => a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : a[1] < b[1] ? -1 : a[1] > b[1] ? 1 : 0);
          }
        }
        const at = connection.lastIndexOf('@');
        if (at < 1) return null;
        let credentials = legacy ? connection.slice(0, at) : decodeURIComponent(connection.slice(0, at));
        if (!credentials.includes(':')) credentials = decodeBase64(credentials);
        const separator = credentials.indexOf(':');
        if (separator < 1 || separator === credentials.length - 1) return null;
        key = {
          protocol, ...parseEndpoint(connection.slice(at + 1).split('/')[0]), cipher: credentials.slice(0, separator),
          password: credentials.slice(separator + 1), params,
        };
      } else if (['vless', 'trojan', 'hysteria2'].includes(protocol)) {
        key = { protocol, ...splitConnection(body) };
        if (protocol === 'vless' && UUID.test(key.credentials)) key.credentials = key.credentials.toLowerCase();
      } else {
        return null;
      }
      return JSON.stringify(stableValue(key));
    } catch (_) {
      return null;
    }
  }

  function isUriQuery(query) {
    return URI_QUERY.test(query) || NODE_PREFIX.test(query);
  }

  function formatEndpoint(server, port) {
    const host = String(server || '');
    return (host.includes(':') && !host.startsWith('[') ? '[' + host + ']' : host) + (port ? ':' + port : '');
  }

  function searchNodes(nodes, query) {
    const input = String(query || '').trim();
    if (!input) return [];
    if (isUriQuery(input)) {
      const key = canonicalNodeKey(input);
      if (!key) return [];
      return nodes.filter((node) => {
        const keys = Array.isArray(node.match_keys) ? node.match_keys : [node.uri, ...(node.uris || [])].map(canonicalNodeKey);
        return keys.includes(key);
      });
    }
    if (/^(?:\[[^\]]+\]|[^\s:]+):\d+$/.test(input)) {
      try {
        const endpoint = parseEndpoint(input);
        return nodes.filter((node) => node.server === endpoint.server && node.port === endpoint.port);
      } catch (_) { return []; }
    }
    if (input.includes(':') || /^\[.*\]$/.test(input) || /^\d+\.\d+\.\d+\.\d+$/.test(input)) {
      try {
        const server = normalizeServer(input);
        if (server.includes(':') || /^\d+\.\d+\.\d+\.\d+$/.test(server)) return nodes.filter((node) => node.server === server);
      } catch (_) { /* Other terms continue through keyword matching. */ }
    }
    let decodedInput = input;
    try { decodedInput = decodeURIComponent(input); } catch (_) { /* Plain keyword input can contain literal percent signs. */ }
    const terms = decodedInput.toLowerCase().split(/\s+/);
    return nodes.filter((node) => {
      const text = [node.search_text || '', node.name || '', ...(node.names || []), node.protocol || '', node.server || '', formatEndpoint(node.server, node.port)].join(' ').toLowerCase();
      return terms.every((term) => text.includes(term));
    });
  }

  function safeHttpUrl(value) {
    if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return null;
    try {
      const url = new URL(value);
      return ['https:', 'http:'].includes(url.protocol) && url.hostname ? url.href : null;
    } catch (_) {
      return null;
    }
  }

  function nodeValidation(node) {
    const validation = node && node.validation && typeof node.validation === 'object' ? node.validation : {};
    const labels = { passed: '连通性通过', failed: '连通性失败', unsupported: '验证器不支持', unverified: '未验证' };
    const status = Object.hasOwn(labels, validation.status) ? validation.status : 'unverified';
    return {
      status, label: labels[status],
      latency_ms: status === 'passed' && typeof validation.latency_ms === 'number' && Number.isFinite(validation.latency_ms) && validation.latency_ms >= 0 ? validation.latency_ms : null,
      checked_at: typeof validation.checked_at === 'string' ? validation.checked_at : '',
      reason: typeof validation.reason === 'string' ? validation.reason : '',
      published: status === 'passed' && node.published === true,
    };
  }

  function checkedAtLabel(value) {
    const stamp = Date.parse(value);
    return Number.isFinite(stamp) ? new Date(stamp).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC') : '未记录';
  }

  function initialize(document) {
    const section = document.getElementById('node-search');
    if (!section) return;
    const form = document.getElementById('node-search-form');
    const input = document.getElementById('node-search-input');
    const status = document.getElementById('node-search-status');
    const results = document.getElementById('node-search-results');
    const pagination = document.getElementById('node-search-pagination');
    const previous = document.getElementById('node-search-previous');
    const next = document.getElementById('node-search-next');
    const pageLabel = document.getElementById('node-search-page');
    let index;
    let matches = [];
    let page = 1;
    let request = 0;

    function element(tag, className, text) {
      const item = document.createElement(tag);
      if (className) item.className = className;
      if (text !== undefined) item.textContent = String(text);
      return item;
    }

    async function copyUrl(url, button) {
      try {
        if (root.navigator.clipboard && root.isSecureContext) {
          await root.navigator.clipboard.writeText(url);
        } else {
          const field = element('textarea', 'node-search-copy-field');
          field.value = url;
          document.body.append(field);
          field.select();
          const copied = document.execCommand('copy');
          field.remove();
          if (!copied) throw new Error('Copy failed');
        }
        button.textContent = '已复制';
      } catch (_) {
        button.textContent = '复制失败';
      }
      root.setTimeout(() => { button.textContent = '复制 URL'; }, 1600);
    }

    function renderSource(source, sourceId) {
      const row = element('li', 'node-search-source');
      const info = element('div', 'node-search-source-info');
      const label = element('div', 'node-search-source-label', source.provider || '订阅来源');
      if (source.available === false) label.append(element('span', 'node-search-source-unavailable', '本次采集失败'));
      const originalUrl = typeof source.url === 'string' ? source.url : '';
      const url = safeHttpUrl(originalUrl);
      const address = element(url ? 'a' : 'span', 'node-search-source-url', originalUrl || '来源 ' + sourceId);
      if (url) {
        address.href = url;
        address.target = '_blank';
        address.rel = 'noopener noreferrer';
      }
      info.append(label, address);
      const actions = element('div', 'node-search-source-actions');
      const copy = element('button', 'node-search-button node-search-copy', '复制 URL');
      copy.type = 'button';
      copy.disabled = !url;
      if (url) copy.addEventListener('click', () => copyUrl(originalUrl, copy));
      actions.append(copy);
      if (typeof source.detail_page === 'string' && source.detail_page) {
        try {
          const detailUrl = new URL(source.detail_page, document.baseURI);
          if (['https:', 'http:'].includes(detailUrl.protocol) && detailUrl.origin === new URL(document.baseURI).origin) {
            const detail = element('a', 'node-search-detail', '来源详情');
            detail.href = detailUrl.href;
            actions.append(detail);
          }
        } catch (_) { /* Invalid source detail URLs do not become links. */ }
      }
      row.append(info, actions);
      return row;
    }

    function renderPage() {
      results.replaceChildren();
      const totalPages = Math.max(1, Math.ceil(matches.length / PAGE_SIZE));
      page = Math.min(Math.max(1, page), totalPages);
      const fragment = document.createDocumentFragment();
      matches.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE).forEach((node) => {
        const row = element('li', 'node-search-result');
        const heading = element('div', 'node-search-result-heading');
        heading.append(element('h3', 'node-search-name', node.name || (node.names || [])[0] || node.server || '未命名节点'));
        const connection = element('div', 'node-search-connection');
        connection.append(element('span', 'node-search-protocol', String(node.protocol || '未知协议').toUpperCase()));
        connection.append(element('code', 'node-search-endpoint', formatEndpoint(node.server, node.port)));
        const validation = nodeValidation(node);
        connection.append(element('span', 'node-validation-badge ' + validation.status, validation.label));
        if (!validation.published) connection.append(element('span', 'node-search-unpublished', '未进入导出'));
        heading.append(connection);
        row.append(heading);
        const evidence = element('p', 'node-validation-evidence');
        const details = [];
        if (validation.latency_ms !== null) details.push('HTTP 探测延迟 ' + Math.round(validation.latency_ms) + ' ms');
        if (validation.checked_at) details.push('验证于 ' + checkedAtLabel(validation.checked_at));
        if (validation.reason) details.push(validation.reason);
        evidence.textContent = details.join(' · ') || '尚无节点连通性实测记录';
        row.append(evidence);
        const sourceIds = [...new Set(Array.isArray(node.source_ids) ? node.source_ids : [])];
        row.append(element('div', 'node-search-source-count', '原始订阅 ' + sourceIds.length));
        const sourceList = element('ul', 'node-search-source-list');
        sourceIds.forEach((sourceId) => sourceList.append(renderSource(index.sources[sourceId] || {}, sourceId)));
        row.append(sourceList);
        fragment.append(row);
      });
      results.append(fragment);
      results.hidden = matches.length === 0;
      pagination.hidden = totalPages <= 1;
      previous.disabled = page === 1;
      next.disabled = page === totalPages;
      pageLabel.textContent = page + ' / ' + totalPages;
      const verified = matches.filter((node) => nodeValidation(node).status === 'passed').length;
      status.textContent = matches.length ? '找到 ' + matches.length + ' 个已采集节点 · 连通性通过 ' + verified + ' 个' : index.nodes.length ? '未找到匹配的已采集节点' : '本次没有采集到节点，尚无可查询记录';
      status.classList.remove('node-search-error');
    }

    function clearResults(message, error) {
      matches = [];
      results.replaceChildren();
      results.hidden = true;
      pagination.hidden = true;
      status.textContent = message;
      status.classList.toggle('node-search-error', Boolean(error));
    }

    const indexCache = root.LeakSSRFreshness.createIndexCache(async () => {
      const snapshot = await root.LeakSSRFreshness.readSnapshot(
        () => root.LeakSSRFreshness.fetchData(new URL('health.json', document.baseURI)),
        () => root.LeakSSRFreshness.fetchData(new URL('sub/node_index.json', document.baseURI))
          .then((data) => {
            if (!data || data.version !== 1 || !Array.isArray(data.nodes) || !data.sources || typeof data.sources !== 'object' || Array.isArray(data.sources)) {
              throw new Error('Invalid index');
            }
            return data;
          }));
      return snapshot.data;
    });

    let submittedQuery = '';
    async function runSearch(preservePage = false) {
      const currentRequest = ++request;
      const query = input.value.trim();
      submittedQuery = query;
      if (!preservePage) page = 1;
      if (!query) {
        section.setAttribute('aria-busy', 'false');
        clearResults('尚未查询', false);
        return;
      }
      if (isUriQuery(query) && !canonicalNodeKey(query)) {
        section.setAttribute('aria-busy', 'false');
        clearResults('节点 URI 无效或协议不受支持', true);
        return;
      }
      clearResults('正在加载节点索引…', false);
      section.setAttribute('aria-busy', 'true');
      try {
        const loaded = await indexCache.read();
        if (currentRequest !== request) return;
        index = loaded;
        matches = searchNodes(index.nodes, query);
        renderPage();
      } catch (_) {
        if (currentRequest !== request) return;
        clearResults('节点索引加载失败，请重新搜索', true);
      } finally {
        if (currentRequest === request) section.setAttribute('aria-busy', 'false');
      }
    }
    form.addEventListener('submit', (event) => { event.preventDefault(); runSearch(); });
    document.addEventListener('leakssr:snapshot', () => {
      indexCache.invalidate();
      ++request;
      if (submittedQuery && input.value.trim() === submittedQuery) runSearch(true);
      else if (submittedQuery) {
        section.setAttribute('aria-busy', 'false');
        clearResults('数据已更新，请重新搜索', false);
      }
    });
    document.getElementById('node-search-clear').addEventListener('click', () => {
      input.value = '';
      submittedQuery = '';
      ++request;
      section.setAttribute('aria-busy', 'false');
      clearResults('尚未查询', false);
      input.focus();
    });
    previous.addEventListener('click', () => { page -= 1; renderPage(); });
    next.addEventListener('click', () => { page += 1; renderPage(); });
  }

  const api = { canonicalNodeKey, searchNodes, safeHttpUrl, isUriQuery, formatEndpoint, nodeValidation, checkedAtLabel };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  root.LeakSSRNodeSearch = api;
  if (root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', () => initialize(root.document));
    else initialize(root.document);
  }
})(typeof window !== 'undefined' ? window : globalThis);
