const assert = require('node:assert/strict');
const test = require('node:test');
const { canonicalNodeKey, searchNodes, safeHttpUrl, nodeValidation } = require('./static/node-search.js');
const { filterSources, protocolCounts, sourceCsv, snapshotState, snapshotNotice, validationSummary, exportCounts } = require('./static/platform.js');
const { sourceNodes } = require('./static/source.js');

const encode = (value) => Buffer.from(value, 'utf8').toString('base64');
const uriNode = (uri, overrides = {}) => ({
  name: 'Tokyo Example', names: ['Tokyo Example', 'Backup alias'],
  protocol: 'vless', server: 'example.com', port: 443,
  uri, uris: [uri], match_keys: [canonicalNodeKey(uri)], ...overrides,
});

test('full URIs ignore display names and query order but retain connection options', () => {
  const uri = 'vless://user@EXAMPLE.com.:443?type=ws&security=tls#Tokyo';
  const renamed = 'vless://user@example.com:443?security=tls&type=ws#Other';
  const different = 'vless://user@example.com:443?security=tls&type=tcp#Other';
  assert.equal(canonicalNodeKey(uri), canonicalNodeKey(renamed));
  assert.notEqual(canonicalNodeKey(uri), canonicalNodeKey(different));
  assert.equal(searchNodes([uriNode(uri)], renamed).length, 1);
  assert.equal(searchNodes([uriNode(uri)], different).length, 0);
});

test('generic URIs accept the default TLS port and spaces in display names', () => {
  assert.equal(canonicalNodeKey('trojan://password@example.com#New name'), canonicalNodeKey('trojan://password@example.com:443#Original'));
  assert.equal(canonicalNodeKey('vless://user@example.com?type=ws#Two words'), canonicalNodeKey('vless://user@example.com:443?type=ws#Other'));
  assert.equal(canonicalNodeKey('vless://user@exam ple.com:443#Name'), null);
  assert.equal(canonicalNodeKey('vless://user@example.com:443?path=%zz#Name'), null);
});

test('plain terms match aliases and host:port case-insensitively with AND semantics', () => {
  const node = uriNode('vless://user@example.com:443#Tokyo');
  assert.deepEqual(searchNodes([node], 'BACKUP example.com:443'), [node]);
  assert.deepEqual(searchNodes([node], 'Tokyo missing'), []);
  assert.deepEqual(searchNodes([node], '   '), []);
});

test('server:port queries compare complete endpoints including normalized IPv6', () => {
  const target = uriNode('vless://user@example.com:443#Tokyo');
  const differentPort = uriNode('vless://user@example.com:4430#Tokyo', {port: 4430});
  const differentHost = uriNode('vless://user@other-example.com:443#Tokyo', {server: 'other-example.com'});
  assert.deepEqual(searchNodes([target, differentPort, differentHost], 'example.com:443'), [target]);
  assert.deepEqual(searchNodes([target], 'EXAMPLE.com.:443'), [target]);
  const ipv6 = uriNode('vless://user@[2001:db8::1]:443#Tokyo', {server: '2001:db8::1'});
  assert.deepEqual(searchNodes([ipv6], '[2001:0db8:0:0:0:0:0:1]:443'), [ipv6]);
  assert.deepEqual(searchNodes([ipv6], '2001:0db8:0:0:0:0:0:1'), [ipv6]);
});

test('percent-encoded URI payloads and VMess defaults match the emitted index identity', () => {
  const config = {ps: 'Original', add: 'EXAMPLE.com...', id: 'A1B2C3D4-1111-2222-3333-123456789ABC'};
  const uri = `vmess://${encode(JSON.stringify(config))}`;
  const key = JSON.parse(canonicalNodeKey(uri));
  assert.equal(key.server, 'example.com');
  assert.equal(key.port, 443);
  assert.deepEqual(key.config, {aid: 0, id: config.id.toLowerCase(), net: 'tcp', scy: 'auto', tls: ''});
  const withEmptyFields = `vmess://${encode(JSON.stringify({...config, net: '', scy: '', tls: null}))}`;
  assert.deepEqual(JSON.parse(canonicalNodeKey(withEmptyFields)).config, {aid: 0, id: config.id.toLowerCase(), net: '', scy: '', tls: null});
  assert.equal(canonicalNodeKey(`vmess://${encode(JSON.stringify({...config, aid: -1}))}`), null);
  assert.equal(canonicalNodeKey(`vmess://${encode(JSON.stringify({...config, aid: ''}))}`), null);
  assert.equal(canonicalNodeKey(`vmess://${encode(JSON.stringify({...config, id: 123}))}`), null);
  const ss = `ss://${encode('aes-256-gcm:password@example.com:8388?plugin=obfs-local')}`;
  assert.equal(canonicalNodeKey(ss), canonicalNodeKey('ss://aes-256-gcm:password@example.com:8388?plugin=obfs-local'));
  assert.equal(canonicalNodeKey(uri.replace(/=/g, '%3D')), canonicalNodeKey(uri));
});

test('VLESS UUID case normalizes without changing password case in other protocols', () => {
  const upper = 'A1B2C3D4-1111-2222-3333-123456789ABC';
  assert.equal(canonicalNodeKey(`vless://${upper}@example.com:443`), canonicalNodeKey(`vless://${upper.toLowerCase()}@example.com:443`));
  assert.notEqual(canonicalNodeKey('trojan://Password@example.com:443'), canonicalNodeKey('trojan://password@example.com:443'));
});

test('international server names normalize to the index DNS spelling', () => {
  assert.equal(canonicalNodeKey('vless://user@例子.测试:443'), canonicalNodeKey('vless://user@xn--fsqu00a.xn--0zwm56d:443'));
  assert.equal(canonicalNodeKey('vless://user@faß.de:443'), canonicalNodeKey('vless://user@fass.de:443'));
});

test('malformed and unsupported URI queries cannot fall back to substring matching', () => {
  const node = uriNode('vless://user@example.com:443#Tokyo', {name: 'vmess://broken'});
  for (const uri of ['vmess://broken', 'vless://user@example.com:bad', 'https://example.com', 'ssr://', 'trojan://@example.com:443']) {
    assert.equal(canonicalNodeKey(uri), null);
    assert.deepEqual(searchNodes([node], uri), []);
  }
});

test('VMess JSON key order and name changes identify the same connection', () => {
  const config = {v: '2', ps: 'Original', add: 'EXAMPLE.com', port: '443', id: 'A1B2C3D4-1111-2222-3333-123456789ABC', aid: '0', net: 'ws', tls: 'tls', path: '/edge'};
  const renamed = {path: '/edge', tls: 'tls', net: 'ws', aid: 0, id: config.id.toLowerCase(), port: 443, add: 'example.com', ps: 'New'};
  assert.equal(canonicalNodeKey(`vmess://${encode(JSON.stringify(config))}`), canonicalNodeKey(`vmess://${encode(JSON.stringify(renamed))}#Alias`));
  assert.notEqual(canonicalNodeKey(`vmess://${encode(JSON.stringify(config))}`), canonicalNodeKey(`vmess://${encode(JSON.stringify({...renamed, path: '/other'}))}`));
});

test('Shadowsocks legacy and SIP002 encodings identify the same connection', () => {
  const legacy = `ss://${encode('aes-256-gcm:p@ss:word@example.com:8388')}#Original`;
  const sip002 = `ss://${encode('aes-256-gcm:p@ss:word')}@EXAMPLE.com:8388#Renamed`;
  const plain = 'ss://aes-256-gcm:p%40ss%3Aword@example.com:8388#Plain';
  assert.equal(canonicalNodeKey(legacy), canonicalNodeKey(sip002));
  assert.equal(canonicalNodeKey(legacy), canonicalNodeKey(plain));
});

test('SSR display metadata and query order do not affect the connection', () => {
  const base = `example.com:443:auth_sha1_v4:aes-256-cfb:tls1.2_ticket_auth:${encode('password')}`;
  const original = `ssr://${encode(`${base}/?obfsparam=${encode('example.com')}&remarks=${encode('Original')}&group=${encode('A')}`)}`;
  const renamed = `ssr://${encode(`${base}/?group=${encode('B')}&remarks=${encode('Renamed')}&obfsparam=${encode('example.com')}`)}`;
  assert.equal(canonicalNodeKey(original), canonicalNodeKey(renamed));
});

test('Hysteria2 aliases, IPv6 spelling, fragments and empty root paths normalize', () => {
  const original = 'hy2://pass@[2001:0DB8:0000:0000:0000:0000:0000:0001]:443/?sni=example.com&insecure=1#Original';
  const renamed = 'hysteria2://pass@[2001:db8::1]:443?insecure=1&sni=example.com#Renamed';
  assert.equal(canonicalNodeKey(original), canonicalNodeKey(renamed));
  assert.notEqual(canonicalNodeKey(renamed), canonicalNodeKey(renamed.replace('pass@', 'other@')));
});

test('subscription links only accept absolute HTTP or HTTPS URLs', () => {
  assert.equal(safeHttpUrl('https://example.com/sub?token=secret'), 'https://example.com/sub?token=secret');
  assert.equal(safeHttpUrl('http://example.com/sub'), 'http://example.com/sub');
  for (const value of ['javascript:alert(1)', 'data:text/html,hello', '//evil.example/sub', '/relative', 'not a URL']) {
    assert.equal(safeHttpUrl(value), null);
  }
});

test('source inventory filters preserve true, false and unknown build states', () => {
  const sources = [
    { provider: 'Available', url: 'https://one.example/sub', available: true, nodes_total: 8, protocols: 'vless:8', source: 'github' },
    { provider: 'Unavailable', url: 'https://two.example/sub', available: false, nodes_total: 0, protocol_counts: { trojan: 2 }, source: 'telegram' },
    { provider: 'Unknown', url: 'https://three.example/sub', nodes_total: null },
  ];
  const filters = { query: '', status: 'all', channel: 'all', protocol: 'all', sort: 'nodes' };
  assert.deepEqual(filterSources(sources, { ...filters, status: 'available' }), [sources[0]]);
  assert.deepEqual(filterSources(sources, { ...filters, status: 'unavailable' }), [sources[1]]);
  assert.deepEqual(filterSources(sources, { ...filters, status: 'unknown' }), [sources[2]]);
  assert.deepEqual(filterSources(sources, { ...filters, query: 'ONE.EXAMPLE', channel: 'github', protocol: 'vless' }), [sources[0]]);
  assert.deepEqual(filterSources(sources, { ...filters, status: 'available', channel: 'telegram' }), []);
  assert.equal(sources[2].available, undefined);
});

test('source response sorting places unknown values after measured zero and positive values', () => {
  const sources = [
    { provider: 'A missing', response_ms: null },
    { provider: 'Z measured', response_ms: 150 },
    { provider: 'Zero measured', response_ms: 0 },
    { provider: 'Also missing' },
  ];
  const rows = filterSources(sources, { status: 'all', channel: 'all', protocol: 'all', sort: 'latency' });
  assert.equal(rows[0].response_ms, 0);
  assert.equal(rows[1].response_ms, 150);
  assert.equal(rows.length, 4);
  assert.equal(sources[0].provider, 'A missing');
});

test('source protocol parsing and CSV export reject invalid counts and spreadsheet formulas', () => {
  assert.deepEqual(protocolCounts({ protocols: 'ss:3, hy2:2, junk:9, trojan:-2' }), { ss: 3, hysteria2: 2 });
  assert.deepEqual(protocolCounts({ protocol_counts: { vless: 0, trojan: null, ss: '3', vmess: 1 } }), { vmess: 1 });
  const csv = sourceCsv([{ provider: '=HYPERLINK("https://evil.example")', available: false, nodes_total: 0, url: 'https://one.example/sub' }]);
  assert.ok(csv.startsWith('\uFEFF'));
  assert.ok(csv.includes('"\'=HYPERLINK(""https://evil.example"")"'));
  assert.ok(csv.includes('"采集失败","0"'));
  assert.ok(csv.includes('"https://one.example/sub"'));
});

test('snapshot state marks failed refresh and stale data honestly with UTC suffix dates', () => {
  const now = Date.parse('2026-10-12T06:00:00Z');
  assert.equal(snapshotState({ build_time_utc: '2026-10-12 05:00:00 UTC' }, now), 'current');
  assert.equal(snapshotState({ build_time_utc: '2026-10-09 05:00:00 UTC' }, now), 'historical');
  assert.equal(snapshotState({ stale: true, refresh_status: 'failed' }, now), 'stale');
  assert.equal(snapshotState({ stale: false, refresh_status: 'failed', nodes_total: 0 }, now), 'failed');
});

test('legacy collected node totals cannot imply verified connectivity or export counts', () => {
  const health = { nodes_total: 35, protocol_counts: { vless: 35 }, region_counts: { hk: 35 }, yaml_nodes_total: 35, yaml_protocol_counts: { vless: 35 } };
  const summary = validationSummary(health);
  assert.equal(summary.status, 'not_run');
  assert.equal(summary.collected, 35);
  assert.equal(summary.verified, null);
  assert.equal(summary.unverified, 35);
  assert.deepEqual(exportCounts(health, 'passwall2'), { total: null, protocols: {}, regions: {} });
  assert.deepEqual(exportCounts(health, 'clash'), { total: null, protocols: {}, regions: {} });
});

test('export quantities use passed nodes while YAML uses its supported passed subset', () => {
  const health = {
    nodes_total: 35, nodes_verified: 5, nodes_failed: 28, nodes_unverified: 2, published_nodes_total: 5,
    validation: { status: 'completed', engine: 'mihomo', checked_at: '2026-10-12T06:00:00Z', vantage_point: '192.0.2.1', probe_urls: ['https://example.com/probe'], timeout_ms: 8000 },
    protocol_counts: { vless: 35 }, region_counts: { hk: 35 },
    verified_protocol_counts: { vless: 5 }, verified_region_counts: { hk: 5 },
    yaml_nodes_total: 4, yaml_protocol_counts: { vless: 4 }, yaml_region_counts: { hk: 4 },
  };
  assert.deepEqual(exportCounts(health, 'passwall2'), { total: 5, protocols: { vless: 5 }, regions: { hk: 5 } });
  assert.deepEqual(exportCounts(health, 'clash'), { total: 4, protocols: { vless: 4 }, regions: { hk: 4 } });
  assert.equal(validationSummary(health).verified, 5);
  assert.equal(validationSummary(health).failed, 28);
  assert.equal(validationSummary(health).checked_at, health.validation.checked_at);
});

test('node validation distinguishes measured latency and unverified publication flags', () => {
  assert.deepEqual(nodeValidation({ published: true }), { status: 'unverified', label: '未验证', latency_ms: null, checked_at: '', reason: '', published: false });
  const passed = nodeValidation({ published: true, validation: { status: 'passed', latency_ms: 0, checked_at: '2026-10-12T06:00:00Z' } });
  assert.equal(passed.label, '连通性通过');
  assert.equal(passed.latency_ms, 0);
  assert.equal(passed.published, true);
  const failed = nodeValidation({ published: false, validation: { status: 'failed', latency_ms: 200, reason: 'timeout' } });
  assert.equal(failed.label, '连通性失败');
  assert.equal(failed.latency_ms, null);
  assert.equal(failed.reason, 'timeout');
  assert.equal(nodeValidation({ validation: { status: 'unsupported' } }).label, '验证器不支持');
});

test('source provenance includes collected failed nodes absent from published provider exports', () => {
  const nodes = [
    { id: 'passed', source_ids: ['abc'], published: true, validation: { status: 'passed' } },
    { id: 'failed', source_ids: ['abc', 'other'], published: false, validation: { status: 'failed' } },
    { id: 'unrelated', source_ids: ['other'] },
  ];
  assert.deepEqual(sourceNodes({ nodes }, 'abc'), nodes.slice(0, 2));
  assert.deepEqual(sourceNodes({}, 'abc'), []);
});

test('stale refresh revokes validated exports while preserving prior collection provenance', () => {
  const health = { stale: true, refresh_status: 'failed', nodes_total: 35, nodes_verified: 0, published_nodes_total: 5, verified_protocol_counts: { vless: 5 }, validation: { status: 'completed' } };
  assert.equal(snapshotNotice(health), '上次采集记录仅供溯源，本次未能验证，已停止发布节点导出。');
  assert.deepEqual(exportCounts(health, 'passwall2'), { total: null, protocols: {}, regions: {} });
});
