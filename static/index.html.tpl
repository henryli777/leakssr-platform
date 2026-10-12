<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#171f1d">
  <meta name="description" content="LeakSSR 订阅聚合运营平台：节点溯源、来源管理与订阅导出。">
  <title>LeakSSR · 订阅聚合运营平台</title>
  <link rel="stylesheet" href="styles.css">
  <link rel="stylesheet" href="node-search.css">
  <script src="vendor/lucide.min.js" defer></script>
  <script src="node-search.js" defer></script>
  <script src="platform.js" defer></script>
</head>
<body data-view="overview">
  <a class="skip-link" href="#main">跳到主要内容</a>
  <aside class="sidebar" aria-label="平台导航">
    <a class="brand" href="#overview" aria-label="LeakSSR 运行概览"><span class="brand-mark"><i data-lucide="network" aria-hidden="true"></i></span><span>LeakSSR<span class="brand-caption">SUBSCRIPTION OPERATIONS</span></span></a>
    <div class="workspace-label">运营工作台 <span>PUBLIC</span></div>
    <nav class="main-nav">
      <a href="#overview" data-view-link="overview" class="active" aria-current="page"><i data-lucide="layout-dashboard" aria-hidden="true"></i><span>运行概览</span></a>
      <a href="#search" data-view-link="search"><i data-lucide="search" aria-hidden="true"></i><span>节点溯源</span></a>
      <a href="#sources" data-view-link="sources"><i data-lucide="radio-tower" aria-hidden="true"></i><span>订阅来源</span><span class="nav-count" id="nav-source-count">—</span></a>
      <a href="#exports" data-view-link="exports"><i data-lucide="download" aria-hidden="true"></i><span>导出中心</span></a>
    </nav>
    <div class="sidebar-bottom">
      <a href="https://github.com/henryli777/leakssr-platform" target="_blank" rel="noopener noreferrer"><i data-lucide="github" aria-hidden="true"></i><span>项目仓库</span><i data-lucide="arrow-up-right" aria-hidden="true"></i></a>
      <div class="sidebar-status"><span class="status-dot"></span>公开数据工作台</div>
      <span class="sidebar-version">LeakSSR Platform</span>
    </div>
  </aside>
  <div class="app-shell">
    <header class="topbar">
      <div class="breadcrumb"><span>工作台</span><span class="breadcrumb-divider">/</span><strong id="breadcrumb-current">运行概览</strong></div>
      <div class="topbar-actions"><span class="snapshot-status" id="snapshot-status"><span class="status-dot muted"></span>正在载入</span><button class="icon-button" type="button" id="refresh-data" title="刷新构建数据" aria-label="刷新构建数据"><i data-lucide="refresh-cw" aria-hidden="true"></i></button><a class="icon-button" href="https://leakssr.coinexo.top" title="平台首页" aria-label="平台首页"><i data-lucide="globe-2" aria-hidden="true"></i></a></div>
    </header>
    <main id="main" tabindex="-1">
      <div class="page-heading"><div><p class="eyebrow" id="page-eyebrow">订阅聚合运营平台</p><h1 id="page-title">LeakSSR <span>运行概览</span></h1></div><div class="heading-actions"><a class="button secondary" href="#sources"><i data-lucide="radio-tower" aria-hidden="true"></i>订阅来源</a><a class="button primary" href="#exports"><i data-lucide="download" aria-hidden="true"></i>导出订阅</a></div></div>
      <div class="data-notice" id="data-notice" role="status" hidden><i data-lucide="clock-3" aria-hidden="true"></i><span id="data-notice-text"></span></div>
      <section class="overview-only metrics-band" aria-label="本次构建指标">
        <div class="metric"><div class="metric-label">聚合节点<i data-lucide="network" aria-hidden="true"></i></div><div class="metric-value" id="metric-nodes">—</div><div class="metric-detail">当前聚合输出</div></div>
        <div class="metric"><div class="metric-label">可用订阅<i data-lucide="circle-check" aria-hidden="true"></i></div><div class="metric-value"><span id="metric-alive">—</span><span class="metric-unit"> / <span id="metric-total">—</span></span></div><div class="metric-detail" id="metric-availability">构建时检测结果</div></div>
        <div class="metric"><div class="metric-label">下次刷新<i data-lucide="refresh-cw" aria-hidden="true"></i></div><div class="metric-value metric-time" id="metric-new">—</div><div class="metric-detail" id="metric-removed">定时采集状态</div></div>
        <div class="metric"><div class="metric-label">最近构建<i data-lucide="clock-3" aria-hidden="true"></i></div><div class="metric-value metric-time" id="metric-build">—</div><div class="metric-detail" id="metric-date">北京时间 UTC+8</div></div>
      </section>
      <section id="node-search" class="node-search" aria-labelledby="node-search-title" aria-busy="false">
        <div class="section-heading"><div><p class="section-kicker">NODE LOOKUP</p><h2 id="node-search-title">节点溯源</h2></div><span class="section-meta">节点索引 · 原始订阅</span></div>
        <form id="node-search-form" class="node-search-form" role="search">
          <div class="node-search-field"><i data-lucide="search" aria-hidden="true"></i><label class="sr-only" for="node-search-input">节点名称、服务器、IP、端口或完整节点 URI</label><input type="search" id="node-search-input" class="node-search-input" placeholder="搜索节点名称、IP、域名，或粘贴完整节点 URI" autocomplete="off" spellcheck="false"><button type="button" id="node-search-clear" class="node-search-button node-search-clear" aria-label="清空搜索" title="清空搜索"><i data-lucide="x" aria-hidden="true"></i></button></div>
          <button type="submit" class="node-search-button node-search-submit"><i data-lucide="search" aria-hidden="true"></i><span>查询来源</span></button>
        </form>
        <div class="search-status-line"><p id="node-search-status" class="node-search-status" role="status" aria-live="polite">尚未查询</p><span class="search-index-count" id="search-index-count"></span></div>
        <ul id="node-search-results" class="node-search-results" hidden></ul>
        <div id="node-search-pagination" class="node-search-pagination" hidden><button type="button" id="node-search-previous" class="node-search-button" aria-label="上一页"><i data-lucide="chevron-left" aria-hidden="true"></i></button><span id="node-search-page" class="node-search-page"></span><button type="button" id="node-search-next" class="node-search-button" aria-label="下一页"><i data-lucide="chevron-right" aria-hidden="true"></i></button></div>
      </section>
      <div class="overview-only distribution-grid">
        <section class="distribution-section" aria-labelledby="protocol-title"><div class="section-heading"><h2 id="protocol-title">协议分布</h2><span class="section-meta">聚合节点</span></div><div class="distribution-list" id="protocol-distribution"><p class="empty-copy">正在载入协议数据</p></div></section>
        <section class="distribution-section" aria-labelledby="region-title"><div class="section-heading"><h2 id="region-title">地区分布</h2><span class="section-meta">构建识别结果</span></div><div class="region-grid" id="region-distribution"><p class="empty-copy">正在载入地区数据</p></div></section>
      </div>
      <section class="overview-only source-overview" aria-labelledby="source-overview-title"><div class="section-heading"><div><p class="section-kicker">SOURCE INVENTORY</p><h2 id="source-overview-title">订阅来源概况</h2></div><a class="text-link" href="#sources">全部来源<i data-lucide="arrow-right" aria-hidden="true"></i></a></div><div class="source-channel-strip" id="source-channel-strip"><p class="empty-copy">正在载入来源数据</p></div><div class="compact-source-list" id="recent-sources"></div></section>
      <section id="sources-view" class="view-section" hidden aria-labelledby="sources-title"><div class="section-heading"><h2 id="sources-title">来源清单 <span class="count-label" id="source-list-count">—</span></h2><button type="button" class="button secondary small" id="export-source-csv"><i data-lucide="file-down" aria-hidden="true"></i>导出清单</button></div>
        <form class="source-toolbar" id="source-filter-form"><div class="filter-search"><i data-lucide="search" aria-hidden="true"></i><label class="sr-only" for="source-query">搜索来源</label><input type="search" id="source-query" placeholder="来源名称、域名或 URL" autocomplete="off"></div><div class="filter-control"><label for="source-status">状态</label><select id="source-status"><option value="all">全部状态</option><option value="available">可用</option><option value="unavailable">本次不可用</option><option value="unknown">状态未知</option></select></div><div class="filter-control"><label for="source-channel">渠道</label><select id="source-channel"><option value="all">全部渠道</option><option value="google">Google</option><option value="github">GitHub</option><option value="telegram">Telegram</option><option value="other">其他 / 未记录</option></select></div><div class="filter-control"><label for="source-protocol">协议</label><select id="source-protocol"><option value="all">全部协议</option></select></div><div class="filter-control"><label for="source-sort">排序</label><select id="source-sort"><option value="nodes">节点数降序</option><option value="latency">响应时间升序</option><option value="quality">评分降序</option><option value="name">来源名称</option><option value="newest">发现日期降序</option></select></div><button type="button" class="icon-button reset-filters" id="source-filter-reset" title="重置筛选" aria-label="重置筛选"><i data-lucide="rotate-ccw" aria-hidden="true"></i></button></form>
        <div class="source-results-heading"><span id="source-results-status" role="status" aria-live="polite">正在载入来源清单</span><label class="page-size-label" for="source-page-size">每页 <select id="source-page-size"><option value="20">20</option><option value="50">50</option><option value="100">100</option></select> 条</label></div>
        <div class="table-scroll"><table class="source-table"><thead><tr><th scope="col">订阅来源</th><th scope="col">状态</th><th scope="col">节点</th><th scope="col">协议</th><th scope="col">响应时间</th><th scope="col">渠道</th><th scope="col">发现日期</th><th scope="col" class="action-column">操作</th></tr></thead><tbody id="source-table-body"></tbody></table></div>
        <div id="source-table-empty" class="empty-state" hidden><i data-lucide="inbox" aria-hidden="true"></i><h3 id="source-empty-title">暂无来源记录</h3><p id="source-empty-copy">本次构建尚未生成来源清单。</p></div>
        <div class="table-pagination"><span id="source-range">—</span><div><button class="icon-button" type="button" id="source-previous" aria-label="上一页" title="上一页" disabled><i data-lucide="chevron-left" aria-hidden="true"></i></button><span id="source-page-label">1 / 1</span><button class="icon-button" type="button" id="source-next" aria-label="下一页" title="下一页" disabled><i data-lucide="chevron-right" aria-hidden="true"></i></button></div></div>
      </section>
      <section id="exports-view" class="view-section" hidden aria-labelledby="exports-title"><div class="section-heading"><div><p class="section-kicker">SUBSCRIPTION EXPORTS</p><h2 id="exports-title">聚合订阅</h2></div><span class="section-meta" id="export-build-time">构建输出</span></div><div class="export-list" id="aggregate-exports"></div><div class="section-heading export-section-heading"><h2>按协议导出</h2><div class="segmented" role="group" aria-label="导出格式"><button type="button" class="active" data-export-format="passwall2" aria-pressed="true">PassWall2</button><button type="button" data-export-format="clash" aria-pressed="false">Clash</button></div></div><div class="export-list" id="protocol-exports"></div><div class="section-heading export-section-heading"><h2>按地区导出</h2></div><div class="export-list" id="region-exports"></div></section>
    </main>
    <footer class="app-footer"><span>LeakSSR <span class="footer-divider">/</span> 公开订阅聚合</span><span id="footer-update">构建时间载入中</span><a href="https://github.com/henryli777/leakssr-platform" target="_blank" rel="noopener noreferrer">GitHub<i data-lucide="arrow-up-right" aria-hidden="true"></i></a></footer>
  </div>
  <nav class="mobile-nav" aria-label="移动端导航"><a href="#overview" data-view-link="overview" class="active" aria-current="page"><i data-lucide="layout-dashboard" aria-hidden="true"></i><span>概览</span></a><a href="#search" data-view-link="search"><i data-lucide="search" aria-hidden="true"></i><span>溯源</span></a><a href="#sources" data-view-link="sources"><i data-lucide="radio-tower" aria-hidden="true"></i><span>来源</span></a><a href="#exports" data-view-link="exports"><i data-lucide="download" aria-hidden="true"></i><span>导出</span></a></nav>
  <div class="toast" id="toast" role="status" aria-live="polite" hidden></div>
</body>
</html>
