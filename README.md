# LeakSSR Platform

公开订阅聚合与节点溯源工作台。正式部署地址：**[leakssr.coinexo.top](https://leakssr.coinexo.top/)**

[GitHub](https://github.com/henryli777/leakssr-platform) · [部署说明](DEPLOYMENT.md) · [Apache-2.0](LICENSE)

## 平台能力

- 运行概览：可用来源、节点与协议分布、实际构建时间和失败状态。
- 节点溯源：按名称、域名/IP、服务器端口、UUID 片段或完整 URI，反查全部已采集订阅来源。
- 来源管理：状态/协议/渠道筛选、排序、分页、CSV 导出、每源详情和节点下载。
- 订阅导出：通用 URI 与 Clash Provider，可按协议和订阅标签识别的地区分类。
- 每 30 分钟刷新来源；原子发布快照，全失败时保留上一份数据并标记过期。

完整 URI 按连接配置匹配，忽略显示名称和参数顺序。多个关键词按同时包含搜索。
同一服务器上的不同凭据不会合并，一个节点出现在多个订阅时保留所有来源。
查询仅覆盖本平台已采集的数据，不能凭空推算未采集过的订阅链接。

## 本地运行

需要 Python 3.11+；Node 仅用于运行前端单元测试。

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-platform.txt
.venv/bin/python platform_build.py --output-dir dist
.venv/bin/python platform_refresh.py --output-dir dist --sources data/live_urls.json
.venv/bin/python -m http.server 8765 --directory dist --bind 127.0.0.1
```

打开 `http://127.0.0.1:8765/`。刷新不需要 SerpAPI 密钥，不触发爬虫或通知。
`data/live_urls.json` 是从原公开项目导入的候选列表，不保证当前全部有效。
首次全失败时展示空数据；已有快照时继续提供旧数据，并明确提示刷新失败。

```sh
.venv/bin/python node_lookup.py 'example.com:443'
.venv/bin/python node_lookup.py 'vless://UUID@example.com:443?security=tls#名称' --json
.venv/bin/python -m unittest test_node_lookup test_platform_refresh test_platform_build
node --test test_node_search.js
```

## 输出与边界

| 文件 | 用途 |
| --- | --- |
| `sub/all.txt` | 去重后的完整原始节点 URI |
| `sub/all.yaml` | Clash/Mihomo 节点 Provider，不是完整客户端配置 |
| `sub/proto/*.txt`、`sub/clash/*.yaml` | 协议分类 |
| `sub/regions/*/` | 按节点名称识别的地区分类，不代表地理 IP 检测 |
| `sub/urls.txt` | 本次快照的可用订阅链接 |
| `sub/node_index.json` | 节点与多来源反查索引 |
| `sub/url_meta.json`、`health.json` | 来源状态与构建健康信息 |

支持 `ss`、`ssr`、`vmess`、`vless`、`trojan`、`hysteria2` URI，支持原文和 Base64 订阅。
纯 Clash YAML 来源暂标记为不支持。无法无损转换的 URI 仍进入 TXT 和反查索引，
不进入 YAML；`yaml_skipped_total` 单独报告。可用表示订阅内容有效，不代表节点连通性或测速结果。

这是公开数据平台，订阅 URL 和节点凭据在输出中可见。只使用允许公开分发的来源，
不要把私人订阅、密钥、SSH 凭据或管理接口上传到仓库或公网。

## 部署

平台运行于 `43.108.37.222`，Nginx 提供静态页面，独立受限 systemd 服务定时刷新。
源代码与虚拟环境由 root 持有，服务只可写公开生成数据；发布采用独立目录与原子切换。
详见 [DEPLOYMENT.md](DEPLOYMENT.md)。GitHub 仓库主页链接指向正式域名，
域名由服务器托管，不与 GitHub Pages CNAME 混用。

## 来源

由 [henryli777/google_ssr_actions](https://github.com/henryli777/google_ssr_actions) 迁移演进，
初始导入提交 `728a8c21ab3f414e4fef4cae36c82dfe518b20ae`，保留 Apache-2.0 许可证。
新仓库只发布平台运行、页面、测试与部署文件；原采集器及历史样本继续保留在父项目
`google_ssr_actions/` 中。Lucide 0.468.0 的 ISC 许可证位于 `static/vendor/LICENSE`。
