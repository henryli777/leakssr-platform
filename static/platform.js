(function (root) {
  'use strict';

  const PROTOCOLS = { ss: 'Shadowsocks', ssr: 'ShadowsocksR', vmess: 'VMess', vless: 'VLESS', trojan: 'Trojan', hysteria2: 'Hysteria2' };
  const REGIONS = { hk: '中国香港', jp: '日本', us: '美国', sg: '新加坡', tw: '中国台湾', kr: '韩国', de: '德国', uk: '英国', gb: '英国', ca: '加拿大', au: '澳大利亚', fr: '法国', nl: '荷兰', other: '其他地区', unknown: '未识别' };
  const CHANNELS = { google: 'Google', github: 'GitHub', telegram: 'Telegram', other: '其他 / 未记录' };
  const VIEWS = { overview: '运行概览', search: '节点溯源', sources: '订阅来源', exports: '导出中心' };
  const SOURCE_ID = /^[a-f0-9]{12}$/;

  function snapshotState(health, now = Date.now()) {
    if (health.stale === true) return 'stale';
    if (health.refresh_status === 'failed') return 'failed';
    if (health.sample_data === true || health.dataset_type === 'sample' || health.data_status === 'sample') return 'sample';
    const stamp = String(health.build_time_utc || '').replace(/ UTC$/, '').replace(' ', 'T');
    const date = Date.parse(/Z$|[+-]\d\d:\d\d$/.test(stamp) ? stamp : stamp + 'Z');
    return Number.isFinite(date) && now - date > 48 * 3600000 ? 'historical' : 'current';
  }

  function number(value) {
    return typeof value === 'number' && Number.isFinite(value) && value >= 0 ? value : null;
  }

  function safeHttpUrl(value) {
    if (typeof value !== 'string' || !/^https?:\/\//i.test(value)) return null;
    try {
      const url = new URL(value);
      return ['http:', 'https:'].includes(url.protocol) && url.hostname ? url.href : null;
    } catch (_) { return null; }
  }

  function protocolCounts(source) {
    const counts = {};
    if (source && source.protocol_counts && typeof source.protocol_counts === 'object' && !Array.isArray(source.protocol_counts)) {
      Object.entries(source.protocol_counts).forEach(([key, value]) => {
        const protocol = key.toLowerCase() === 'hy2' ? 'hysteria2' : key.toLowerCase();
        if (Object.hasOwn(PROTOCOLS, protocol) && number(value) !== null && value > 0) counts[protocol] = value;
      });
    }
    if (!Object.keys(counts).length && source && typeof source.protocols === 'string') {
      source.protocols.split(',').forEach((entry) => {
        const match = /^\s*([a-z0-9]+)\s*:\s*(\d+)\s*$/i.exec(entry);
        if (!match) return;
        const protocol = match[1].toLowerCase() === 'hy2' ? 'hysteria2' : match[1].toLowerCase();
        const count = Number(match[2]);
        if (Object.hasOwn(PROTOCOLS, protocol) && Number.isSafeInteger(count) && count > 0) counts[protocol] = count;
      });
    }
    return counts;
  }

  function sourceName(source) {
    if (typeof source.provider === 'string' && source.provider) return source.provider;
    if (typeof source.host === 'string' && source.host) return source.host;
    const url = safeHttpUrl(source.url);
    return url ? new URL(url).host : '未命名来源';
  }

  function sourceChannel(source) {
    return Object.hasOwn(CHANNELS, source.source) && source.source !== 'other' ? source.source : 'other';
  }

  function filterSources(sources, filters) {
    const query = String(filters.query || '').trim().toLowerCase();
    const rows = sources.filter((source) => {
      if (query && ![sourceName(source), source.url || '', source.id || ''].join(' ').toLowerCase().includes(query)) return false;
      if (filters.status === 'available' && source.available !== true) return false;
      if (filters.status === 'unavailable' && source.available !== false) return false;
      if (filters.status === 'unknown' && typeof source.available === 'boolean') return false;
      if (filters.channel !== 'all' && sourceChannel(source) !== filters.channel) return false;
      if (filters.protocol !== 'all' && !Object.hasOwn(protocolCounts(source), filters.protocol)) return false;
      return true;
    });
    rows.sort((a, b) => {
      let comparison = 0;
      if (filters.sort === 'name') comparison = sourceName(a).localeCompare(sourceName(b), 'zh-CN');
      else if (filters.sort === 'latency') comparison = (number(a.response_ms) ?? Infinity) - (number(b.response_ms) ?? Infinity);
      else if (filters.sort === 'quality') comparison = (number(b.quality_score) ?? -1) - (number(a.quality_score) ?? -1);
      else if (filters.sort === 'newest') comparison = String(b.first_seen || '').localeCompare(String(a.first_seen || ''));
      else comparison = (number(b.nodes_total) ?? -1) - (number(a.nodes_total) ?? -1);
      return (!Number.isNaN(comparison) && comparison !== 0) ? comparison : sourceName(a).localeCompare(sourceName(b), 'zh-CN');
    });
    return rows;
  }

  function csvValue(value) {
    const text = String(value ?? '');
    const safe = /^[=+@\-\t\r]/.test(text) ? "'" + text : text;
    return '"' + safe.replace(/"/g, '""') + '"';
  }

  function sourceCsv(sources) {
    const rows = [['来源', '状态', '节点数', '协议', '响应时间(ms)', '渠道', '发现日期', 'URL']];
    sources.forEach((source) => rows.push([
      sourceName(source), source.available === true ? '可用' : source.available === false ? '本次不可用' : '未知',
      number(source.nodes_total) ?? '', Object.entries(protocolCounts(source)).map(([protocol, count]) => protocol + ':' + count).join(', '),
      number(source.response_ms) ?? '', CHANNELS[sourceChannel(source)], source.first_seen || '', source.url || '',
    ]));
    return '\uFEFF' + rows.map((row) => row.map(csvValue).join(',')).join('\r\n');
  }

  function initialize(document) {
    const app = document.getElementById('source-table-body');
    if (!app) return;
    const state = { health: null, sources: [], filtered: [], sourceLoaded: false, sourceError: false, page: 1, pageSize: 20, format: 'passwall2', request: 0, toastTimer: null };
    const get = (id) => document.getElementById(id);
    const format = (value) => number(value) === null ? '—' : new Intl.NumberFormat('zh-CN').format(value);

    function element(tag, className, text) {
      const item = document.createElement(tag);
      if (className) item.className = className;
      if (text !== undefined) item.textContent = String(text);
      return item;
    }

    function icon(name) {
      const item = element('i');
      item.dataset.lucide = name;
      item.setAttribute('aria-hidden', 'true');
      return item;
    }

    function refreshIcons() {
      if (root.lucide && typeof root.lucide.createIcons === 'function') root.lucide.createIcons({ attrs: { 'stroke-width': 1.7 } });
    }

    function iconButton(name, label, callback) {
      const button = element('button', 'icon-button');
      button.type = 'button';
      button.title = label;
      button.setAttribute('aria-label', label);
      button.append(icon(name));
      button.addEventListener('click', callback);
      return button;
    }

    function toast(message) {
      root.clearTimeout(state.toastTimer);
      get('toast').textContent = message;
      get('toast').hidden = false;
      state.toastTimer = root.setTimeout(() => { get('toast').hidden = true; }, 2200);
    }

    async function copy(value) {
      try {
        if (root.navigator.clipboard && root.isSecureContext) await root.navigator.clipboard.writeText(value);
        else {
          const field = element('textarea', 'copy-field');
          field.value = value;
          document.body.append(field);
          field.select();
          const copied = document.execCommand('copy');
          field.remove();
          if (!copied) throw new Error('Copy failed');
        }
        toast('订阅链接已复制');
      } catch (_) { toast('复制失败，请从链接地址栏复制'); }
    }

    function statusBadge(source) {
      const available = source.available;
      const badge = element('span', 'badge ' + (available === true ? 'available' : available === false ? 'unavailable' : 'unknown'));
      badge.append(icon(available === true ? 'circle-check' : available === false ? 'circle-minus' : 'circle-help'), document.createTextNode(available === true ? '可用' : available === false ? '不可用' : '未知'));
      if (available === false) badge.title = '本次构建检测时不可用';
      return badge;
    }

    function setView() {
      const candidate = root.location.hash.slice(1);
      const view = Object.hasOwn(VIEWS, candidate) ? candidate : 'overview';
      document.body.dataset.view = view;
      document.title = 'LeakSSR · ' + VIEWS[view];
      get('breadcrumb-current').textContent = VIEWS[view];
      get('page-eyebrow').textContent = '订阅聚合运营平台';
      const title = get('page-title');
      title.replaceChildren(document.createTextNode('LeakSSR '), element('span', '', VIEWS[view]));
      document.querySelectorAll('[data-view-link]').forEach((link) => {
        const active = link.dataset.viewLink === view;
        link.classList.toggle('active', active);
        if (active) link.setAttribute('aria-current', 'page');
        else link.removeAttribute('aria-current');
      });
      get('sources-view').hidden = view !== 'sources';
      get('exports-view').hidden = view !== 'exports';
      get('main').scrollIntoView({ block: 'start' });
    }

    function updateHealth(health) {
      state.health = health;
      get('metric-nodes').textContent = format(health.nodes_total);
      get('metric-alive').textContent = format(health.source_alive);
      get('metric-total').textContent = format(health.source_total);
      const nextTime = /T(\d{2}:\d{2})/.exec(health.next_run_cn || '');
      get('metric-new').textContent = nextTime ? nextTime[1] : '—';
      const alive = number(health.source_alive);
      const total = number(health.source_total);
      get('metric-availability').textContent = alive !== null && total !== null && total > 0 ? '构建时可用率 ' + (alive / total * 100).toFixed(1) + '%' : '构建时检测结果';
      get('metric-removed').textContent = nextTime ? '每 30 分钟 · 北京时间' : '未提供定时计划';
      const stamp = typeof health.build_time_cn === 'string' ? health.build_time_cn : '';
      const parts = /^(\d{4}-\d{2}-\d{2})[ T](\d{2}:\d{2})/.exec(stamp);
      get('metric-build').textContent = parts ? parts[2] : '—';
      get('metric-date').textContent = parts ? parts[1] + ' · 北京时间' : '构建时间未提供';
      get('footer-update').textContent = stamp ? '数据更新于 ' + stamp.replace(/ CST$/, '') + ' UTC+8' : '构建时间未提供';
      get('export-build-time').textContent = stamp ? parts ? parts[1] + ' ' + parts[2] + ' 构建' : '构建输出' : '构建时间未提供';
      get('search-index-count').textContent = number(health.nodes_total) !== null ? format(health.nodes_total) + ' 个聚合节点' : '';
      const freshness = snapshotState(health);
      const labels = { current: health.refresh_status === 'partial' ? '部分来源可用' : '构建记录已载入', stale: '保留上次快照', failed: '本次刷新失败', sample: '示例构建记录', historical: '历史构建记录' };
      get('snapshot-status').replaceChildren(element('span', 'status-dot' + (freshness !== 'current' ? ' muted' : '')), document.createTextNode(labels[freshness]));
      get('data-notice').classList.toggle('error', freshness === 'failed' || freshness === 'stale');
      get('data-notice').hidden = freshness === 'current';
      get('data-notice-text').textContent = freshness === 'stale' ? '最近一次刷新全部失败，继续提供上一份快照。来源清单与节点记录为上次成功采集结果。' : freshness === 'failed' ? '本次没有可用来源，尚无可供导出的节点。' : freshness === 'sample' ? '当前展示示例构建记录。' : freshness === 'historical' ? '当前数据来自 ' + (stamp || health.build_time_utc) + '，已超过 48 小时。可用状态为该次构建的检测结果。' : '';
      renderDistributions();
      renderExports();
    }

    function renderDistributions() {
      const health = state.health || {};
      const protocols = health.protocol_counts && typeof health.protocol_counts === 'object' && !Array.isArray(health.protocol_counts) ? health.protocol_counts : {};
      const protocolRows = Object.entries(protocols).filter(([key, count]) => Object.hasOwn(PROTOCOLS, key) && number(count) !== null && count > 0).sort((a, b) => b[1] - a[1]);
      const protocolTotal = protocolRows.reduce((sum, [, count]) => sum + count, 0);
      const target = get('protocol-distribution');
      target.replaceChildren();
      if (!protocolRows.length) target.append(element('p', 'empty-copy', health.protocol_counts ? '本次构建没有协议节点' : '本次构建未提供协议统计'));
      protocolRows.forEach(([key, count]) => {
        const row = element('div', 'distribution-row');
        const track = element('div', 'distribution-bar');
        const bar = element('span');
        bar.style.width = Math.max(1, count / protocolTotal * 100) + '%';
        track.append(bar);
        row.append(element('span', 'distribution-name', PROTOCOLS[key]), track, element('span', 'distribution-count', format(count)));
        target.append(row);
      });
      const regions = health.region_counts && typeof health.region_counts === 'object' && !Array.isArray(health.region_counts) ? health.region_counts : null;
      const regionRows = regions ? Object.entries(regions).filter(([, count]) => number(count) !== null && count > 0).sort((a, b) => b[1] - a[1]).slice(0, 9) : [];
      get('region-distribution').replaceChildren();
      if (!regionRows.length) get('region-distribution').append(element('p', 'empty-copy', regions ? '本次构建没有已识别地区' : '本次构建未提供地区统计'));
      regionRows.forEach(([key, count]) => {
        const item = element('div', 'region-item');
        const label = element('div', 'region-label');
        label.append(icon('map-pin'), document.createTextNode(REGIONS[key] || key));
        const value = element('div', 'region-value', format(count));
        value.append(element('span', '', '节点'));
        item.append(label, value);
        get('region-distribution').append(item);
      });
      refreshIcons();
    }

    function getFilters() {
      return { query: get('source-query').value, status: get('source-status').value, channel: get('source-channel').value, protocol: get('source-protocol').value, sort: get('source-sort').value };
    }

    function renderSources() {
      state.filtered = filterSources(state.sources, getFilters());
      const rows = state.filtered;
      const pages = Math.max(1, Math.ceil(rows.length / state.pageSize));
      state.page = Math.min(Math.max(1, state.page), pages);
      const first = (state.page - 1) * state.pageSize;
      const last = Math.min(first + state.pageSize, rows.length);
      const body = get('source-table-body');
      body.replaceChildren();
      rows.slice(first, last).forEach((source) => {
        const row = element('tr');
        const name = element('td');
        name.append(element('span', 'table-provider', sourceName(source)));
        const url = safeHttpUrl(source.url);
        const address = element(url ? 'a' : 'span', 'table-url', source.url || '未提供订阅 URL');
        if (url) { address.href = url; address.target = '_blank'; address.rel = 'noopener noreferrer'; address.title = source.url; }
        name.append(address);
        const status = element('td');
        status.append(statusBadge(source));
        const nodeCount = element('td');
        nodeCount.append(element('span', 'table-number', format(source.nodes_total)));
        const protocols = element('td');
        const counts = protocolCounts(source);
        Object.keys(counts).forEach((key) => { const badge = element('span', 'badge protocol', key.toUpperCase()); badge.title = format(counts[key]) + ' 个节点'; protocols.append(badge); });
        if (!Object.keys(counts).length) protocols.append(document.createTextNode('—'));
        const latency = element('td', '', number(source.response_ms) === null ? '—' : format(Math.round(source.response_ms)) + ' ms');
        const channel = element('td', '', CHANNELS[sourceChannel(source)]);
        const date = element('td', '', typeof source.first_seen === 'string' ? source.first_seen : '—');
        const actions = element('td');
        const actionGroup = element('div', 'table-actions');
        const copyButton = iconButton('copy', '复制 ' + sourceName(source) + ' 的订阅链接', () => copy(source.url));
        copyButton.disabled = !url;
        actionGroup.append(copyButton);
        if (SOURCE_ID.test(source.id || '')) {
          const detail = element('a', 'icon-button');
          detail.href = 'source.html?id=' + source.id;
          detail.title = '来源详情';
          detail.setAttribute('aria-label', '查看 ' + sourceName(source) + ' 的来源详情');
          detail.append(icon('arrow-up-right'));
          actionGroup.append(detail);
        }
        actions.append(actionGroup);
        row.append(name, status, nodeCount, protocols, latency, channel, date, actions);
        body.append(row);
      });
      get('source-results-status').textContent = state.sourceError ? '来源清单加载失败' : state.sourceLoaded ? '共 ' + format(state.sources.length) + ' 个来源 · 筛选结果 ' + format(rows.length) + ' 个' : '正在载入来源清单';
      get('source-range').textContent = rows.length ? '显示 ' + (first + 1) + '–' + last + '，共 ' + format(rows.length) + ' 条' : '0 条记录';
      get('source-page-label').textContent = state.page + ' / ' + pages;
      get('source-previous').disabled = state.page <= 1;
      get('source-next').disabled = state.page >= pages;
      get('source-table-empty').hidden = rows.length > 0 || (!state.sourceLoaded && !state.sourceError);
      get('source-empty-title').textContent = state.sourceError ? '来源清单加载失败' : state.sources.length ? '没有匹配的来源' : '暂无来源记录';
      get('source-empty-copy').textContent = state.sourceError ? '刷新构建数据后重试。' : state.sources.length ? '调整搜索词或筛选条件。' : '本次构建尚未生成来源清单。';
      get('export-source-csv').disabled = !rows.length;
      refreshIcons();
    }

    function renderSourceOverview() {
      const counts = { google: 0, github: 0, telegram: 0, other: 0 };
      state.sources.forEach((source) => { counts[sourceChannel(source)] += 1; });
      get('source-channel-strip').replaceChildren();
      if (state.sourceError) get('source-channel-strip').append(element('p', 'empty-copy', '来源清单加载失败'));
      else Object.keys(CHANNELS).forEach((key) => {
        const item = element('div', 'channel-item');
        const mark = element('span', 'channel-icon');
        mark.append(icon(key === 'github' ? 'github' : key === 'telegram' ? 'send' : key === 'google' ? 'globe-2' : 'folder-open'));
        const label = element('div');
        label.append(element('div', 'channel-name', CHANNELS[key]), element('div', 'channel-value', format(counts[key])));
        item.append(mark, label);
        get('source-channel-strip').append(item);
      });
      const recent = get('recent-sources');
      recent.replaceChildren();
      const rows = filterSources(state.sources, { status: 'all', channel: 'all', protocol: 'all', sort: 'nodes' }).slice(0, 4);
      rows.forEach((source) => {
        const row = element(SOURCE_ID.test(source.id || '') ? 'a' : 'div', 'compact-source-row');
        if (row.tagName === 'A') row.href = 'source.html?id=' + source.id;
        row.append(element('span', 'compact-source-name', sourceName(source)), element('span', 'source-channel', CHANNELS[sourceChannel(source)]), element('span', 'compact-source-count', format(source.nodes_total) + ' 节点'), statusBadge(source));
        recent.append(row);
      });
      if (!rows.length) recent.append(element('div', 'compact-source-row', state.sourceError ? '来源记录暂时无法载入' : '暂无来源记录'));
      get('nav-source-count').textContent = state.sourceError ? '—' : format(state.sources.length);
      get('source-list-count').textContent = state.sourceError ? '' : format(state.sources.length);
      const select = get('source-protocol');
      const previousValue = select.value;
      select.replaceChildren(element('option', '', '全部协议'));
      select.firstChild.value = 'all';
      const protocols = new Set(state.sources.flatMap((source) => Object.keys(protocolCounts(source))));
      Object.keys(PROTOCOLS).forEach((key) => { if (protocols.has(key)) { const option = element('option', '', PROTOCOLS[key]); option.value = key; select.append(option); } });
      select.value = protocols.has(previousValue) ? previousValue : 'all';
      refreshIcons();
    }

    function exportRow(label, description, path, count, mark) {
      const row = element('div', 'export-row');
      const badge = element('span', 'export-icon');
      badge.append(icon(mark || 'file-text'));
      const info = element('div', 'export-info');
      info.append(element('div', 'export-name', label), element('div', 'export-description', description));
      const quantity = element('span', 'export-count', number(count) === null ? '—' : format(count) + ' 节点');
      const actions = element('div', 'export-actions');
      const url = new URL(path, document.baseURI).href;
      actions.append(iconButton('copy', '复制 ' + label + ' 订阅链接', () => copy(url)));
      const open = element('a', 'icon-button');
      open.href = url;
      open.target = '_blank';
      open.rel = 'noopener noreferrer';
      open.title = '打开 ' + label;
      open.setAttribute('aria-label', '打开 ' + label);
      open.append(icon('external-link'));
      const download = element('a', 'icon-button');
      download.href = url;
      download.download = path.split('/').pop();
      download.title = '下载 ' + label;
      download.setAttribute('aria-label', '下载 ' + label);
      download.append(icon('download'));
      actions.append(open, download);
      row.append(badge, info, quantity, actions);
      return row;
    }

    function renderExports() {
      const health = state.health || {};
      const aggregate = get('aggregate-exports');
      aggregate.replaceChildren(
        exportRow('通用节点订阅', '原始节点 URI · all.txt', 'sub/all.txt', health.nodes_total, 'file-text'),
        exportRow('Clash 节点 Provider', '节点集合 · all.yaml', 'sub/all.yaml', health.yaml_nodes_total, 'file-code-2'),
        exportRow('原始订阅来源', '可用来源 URL · urls.txt', 'sub/urls.txt', null, 'link'),
      );
      const protocolCounts = state.format === 'clash' ? health.yaml_protocol_counts : health.protocol_counts;
      const protocols = protocolCounts && typeof protocolCounts === 'object' ? protocolCounts : {};
      const protocolTarget = get('protocol-exports');
      protocolTarget.replaceChildren();
      Object.keys(PROTOCOLS).forEach((key) => {
        if (number(protocols[key]) !== null && protocols[key] > 0) {
          const path = 'sub/' + (state.format === 'clash' ? 'clash' : 'proto') + '/' + key + (state.format === 'clash' ? '.yaml' : '.txt');
          protocolTarget.append(exportRow(PROTOCOLS[key], state.format === 'clash' ? 'Clash · YAML' : 'PassWall2 · 节点 URI', path, protocols[key], 'network'));
        }
      });
      if (!protocolTarget.childNodes.length) protocolTarget.append(element('p', 'empty-copy', '暂无协议分类导出'));
      const regionCounts = state.format === 'clash' ? health.yaml_region_counts : health.region_counts;
      const regions = regionCounts && typeof regionCounts === 'object' ? regionCounts : {};
      const regionTarget = get('region-exports');
      regionTarget.replaceChildren();
      Object.entries(regions).filter(([key, count]) => ['hk', 'jp', 'us', 'sg', 'tw', 'kr', 'uk', 'de', 'fr'].includes(key) && number(count) !== null && count > 0).sort((a, b) => b[1] - a[1]).forEach(([key, count]) => {
        const path = 'sub/regions/' + key + (state.format === 'clash' ? '/clash.yaml' : '/passwall2.txt');
        regionTarget.append(exportRow(REGIONS[key], state.format === 'clash' ? 'Clash · YAML' : 'PassWall2 · 节点 URI', path, count, 'map-pin'));
      });
      if (!regionTarget.childNodes.length) regionTarget.append(element('p', 'empty-copy', '暂无地区分类导出'));
      refreshIcons();
    }

    async function fetchJson(path, validator) {
      const response = await root.fetch(new URL(path, document.baseURI), { cache: 'no-cache' });
      if (!response.ok) throw new Error('HTTP ' + response.status);
      const data = await response.json();
      if (!validator(data)) throw new Error('Invalid data');
      return data;
    }

    async function loadData() {
      const request = ++state.request;
      get('refresh-data').disabled = true;
      get('refresh-data').classList.add('is-loading');
      const results = await Promise.allSettled([
        fetchJson('health.json', (data) => data && typeof data === 'object' && !Array.isArray(data)),
        fetchJson('sub/url_meta.json', Array.isArray),
      ]);
      if (request !== state.request) return;
      const [health, sources] = results;
      if (health.status === 'fulfilled') updateHealth(health.value);
      else {
        get('snapshot-status').replaceChildren(element('span', 'status-dot muted'), document.createTextNode('构建数据不可用'));
        get('data-notice').hidden = false;
        get('data-notice').classList.add('error');
        get('data-notice-text').textContent = state.health ? '构建数据刷新失败，保留上次载入的记录。' : '构建数据加载失败，请刷新后重试。';
        if (!state.health) { renderDistributions(); renderExports(); get('footer-update').textContent = '构建数据暂时不可用'; }
      }
      state.sourceError = sources.status === 'rejected';
      if (sources.status === 'fulfilled') {
        state.sources = sources.value.filter((source) => source && typeof source === 'object' && !Array.isArray(source));
        state.sourceLoaded = true;
      }
      renderSourceOverview();
      renderSources();
      get('refresh-data').disabled = false;
      get('refresh-data').classList.remove('is-loading');
    }

    ['source-query', 'source-status', 'source-channel', 'source-protocol', 'source-sort'].forEach((id) => get(id).addEventListener(id === 'source-query' ? 'input' : 'change', () => { state.page = 1; renderSources(); }));
    get('source-filter-form').addEventListener('submit', (event) => event.preventDefault());
    get('source-filter-reset').addEventListener('click', () => { get('source-filter-form').reset(); state.page = 1; renderSources(); });
    get('source-page-size').addEventListener('change', () => { state.pageSize = Number(get('source-page-size').value); state.page = 1; renderSources(); });
    get('source-previous').addEventListener('click', () => { state.page -= 1; renderSources(); });
    get('source-next').addEventListener('click', () => { state.page += 1; renderSources(); });
    get('export-source-csv').addEventListener('click', () => {
      const blob = new Blob([sourceCsv(state.filtered)], { type: 'text/csv;charset=utf-8' });
      const url = URL.createObjectURL(blob);
      const link = element('a');
      link.href = url;
      link.download = 'leakssr-sources-' + new Date().toISOString().slice(0, 10) + '.csv';
      document.body.append(link);
      link.click();
      link.remove();
      root.setTimeout(() => URL.revokeObjectURL(url), 1000);
      toast('来源清单已导出');
    });
    document.querySelectorAll('[data-export-format]').forEach((button) => button.addEventListener('click', () => {
      state.format = button.dataset.exportFormat;
      document.querySelectorAll('[data-export-format]').forEach((item) => { const active = item === button; item.classList.toggle('active', active); item.setAttribute('aria-pressed', String(active)); });
      renderExports();
    }));
    get('refresh-data').addEventListener('click', loadData);
    root.addEventListener('hashchange', setView);
    setView();
    refreshIcons();
    loadData();
  }

  const api = { safeHttpUrl, protocolCounts, sourceName, sourceChannel, filterSources, sourceCsv, number, snapshotState };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  if (root.document) {
    if (root.document.readyState === 'loading') root.document.addEventListener('DOMContentLoaded', () => initialize(root.document));
    else initialize(root.document);
  }
})(typeof window !== 'undefined' ? window : globalThis);
