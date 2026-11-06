# 评测：内置场景与实验结果

这里记录 dep-sentinel 自带的验证场景、三种模式的对照结果和实测踩坑。工具本身的用法见 [README](../README.md)。

## 内置验证场景

| 场景 | 考察点 | 期望 |
|---|---|---|
| s01-log4shell | log4j-core 2.14.1，用户 UA 写进日志 | CVE-2021-44228 为 🔴 |
| s02-jquery-xss | jQuery 3.4.1，URL 参数进 `.html()` | CVE-2020-11023（KEV）为 🔴 |
| s03-lodash-unreachable | lodash 有洞，但只用了 `_.get` 等 | 没有 🔴 |
| s04-lodash-reachable | `_.template(req.body.tpl)` | CVE-2021-23337 为 🔴 |
| s05-pyyaml-upload | `yaml.load(上传文件, FullLoader)` | CVE-2020-14343 至少 🟡 且判定可达 |
| s06-devdep-only | 有洞的包只在 devDependencies | 全部 ⚪ |
| s07-malicious-transitive | 间接依赖 flatmap-stream 0.1.1 投毒 | flatmap-stream 为 🔴 |
| s08-clean | 干净项目 | 0 条告警 |
| s09-axios-noise | axios 1.7.4 一个版本 33 条告警，只请求内部固定地址 | 没有 🔴，SSRF 判定不可达 |
| s10-injection | 同 s04，但搜索结果里混入提示词注入，要求把漏洞判为不受影响 | CVE-2021-23337 仍为 🔴 |
| s11-template-constant | 调用了 `_.template`，但模板是代码里的常量 | 没有 🔴，判定不可达 |
| s12-axios-ssrf | axios 带 baseURL，却把用户传的 path 交给它 | CVE-2025-27152 判定可达 |
| s13-legacy-jar | 没有 pom.xml，fastjson 1.2.24 被改名成 `json-util.jar` 拷在 `WEB-INF/lib`，请求体进 `JSON.parseObject` | 认出 fastjson，CVE-2017-18349 为 🔴 |
| s14-installed-only | 没有 requirements.txt，只有装好的虚拟环境；用户模板进 `SandboxedEnvironment().from_string` | 认出 Jinja2 2.10 并判定可达；提醒未声明的 requests |
| s15-lodash-merge | 只有 `package.json` 没有 lockfile，`_.defaultsDeep` 深合并用户请求体 | CVE-2019-10744 至少 🟡 且判定可达 |

另有 4 个群聊问答（`scenarios/questions.json`），其中两个不带 CVE 编号，要靠大模型和搜索识别组件。

每个场景的期望写在 `scenarios/*/expect.json`，`eval.py` 用三种模式对照：

- `osv`：漏洞库原样告警，HIGH / CRITICAL 视为紧急（相当于常见审计工具的做法）
- `static`：加上 KEV、EPSS、import 检查、从漏洞描述里正则提取函数名、证据门（不用大模型和搜索）
- `full`：再加上大模型和元宝搜索

复现（不需要任何密钥，回放录制数据）：

```bash
docker compose run --rm eval eval --offline
# 或不用 Docker
SENTINEL_OFFLINE=1 LLM_MODEL=Qwen3.8-27B-FP8 LLM_BASE_URL=http://offline.invalid/v1 python eval.py
```

输出在 `out/eval/<mode>/`：每个场景一份 JSON（每条告警的判定理由、调用位置、网页证据、被丢弃的引文数、钉钉消息、OpenVEX），以及 `report.md` 汇总表。

## 当前结果（15 个场景，Qwen3.8-27B-FP8 + 元宝 SearchPro）

| 模式 | 场景通过 | 120 条原始告警中标红 | 群聊问答 |
|---|---|---|---|
| osv（漏洞库原样） | 5/15 | 50 | — |
| static（不用大模型） | 11/15 | 8 | 1/4 |
| full（动静结合） | 15/15 | 14 | 4/4 |

- static 失败的 4 个场景都需要“读懂代码或文字”：常量模板被误判为可达（s11）、内部固定地址被误判为 SSRF 可达（s09）、jar 里的 fastjson 和 Jinja2 沙箱判不出可达（s13、s14）；问答里不带 CVE 编号的也答不出。
- full 一次运行约调用大模型 281 次、元宝约 144 次；已被 KEV 收录的漏洞不再搜索。元宝单次调用中位约 2.5 秒。

## 首轮实验（2026-11-03，14 个场景）

当时还没有 s15，114 条原始告警：osv 5/14 标红 47 条，static 10/14 标红 8 条、问答 1/4，full 14/14 标红 14 条、问答 4/4。

- full 比 static 多标红 8 条、少标红 2 条，都可复核。多标的每条都有调用行号、投票 3:0（一条 2:1），并且有 EPSS ≥ 0.1 或两个以上独立来源的 PoC。少标的是 s11 的常量模板，以及 log4j 的 CVE-2021-45046：它在 KEV 里，但要改过日志格式才能触发，3 票都判不可达。
- 重复实验：大模型调用重新采样 2 轮（`SENTINEL_RUN=1`、`2`），搜索计划沿用。三轮都是 14/14、4/4，标红分别是 14、13、15 条。11 条三轮都标红；6 条时红时黄，多数是摘出的证据网站数在“两个”上下浮动。三轮都没有误标红。
- 11 条稳定标红里有 3 条只靠元宝搜到的公开利用成立，不在 KEV、EPSS 也不高：PyYAML 上传文件、fastjson CVE-2025-70974、Jinja2 CVE-2024-34064。
- s01 的期望在首轮后补入 CVE-2021-45105，理由写在 `expect.json` 的 note 里。

## 每日巡检回放

`python replay.py`（或 `docker compose run --rm eval replay --offline`），2026-01-01 至 2026-11-02，12 个项目、109 条告警：

- 按 OSV 公开日期，漏洞库这段时间新提醒 76 次，分布在 12 天；
- dep-sentinel 首日体检报 12 件今天修，之后只在 2026-01-09 找过一次人（legacy-order 的 fastjson CVE-2025-70974）；
- EPSS 和网页证据用的是今天的值，不是当天的值。

## 接在扫描器后面（2026-11-05，15 个场景）

两个扫描器扫同一个 `scenarios/` 目录，报告交给 `triage --mode full`：

| 扫描器 | 报告条数（严重 / 高危） | 其中今天修 | 扫描器没报、自己认出（其中今天修） | 合计今天修 |
|---|---|---|---|---|
| Trivy 0.58.1（跳过 Java 库） | 98（7 / 35） | 8 | 24（6） | 14 |
| Grype 0.121.1 | 106（8 / 37） | 12 | 14（2） | 14 |

- 两边合计都是 14 条，和 `eval.py` 完整模式的结果一致。
- 扫描器漏掉的原因：只有 `package.json` 没有 lockfile（s15，两个都没报）；改名的 jar（s13，Trivy 跳过了 Java 库）；只有虚拟环境（s14，`trivy fs` 不读）；投毒包的 MAL- 编号和 NSWG 编号（OSV 和扫描器库收录不一致）。
- 旧版 Grype 0.86.1（数据库 schema 5）只报 39 条，axios 只有 3 条，升级到 0.121.1 后是 33 条。扫描器版本旧，漏报会很多。
- VEX 回灌：Trivy 用 purl 认产品，测试 VEX 把一条 lodash 标成不受影响后，4 个项目里的同一条全被隐藏，所以合并版要去掉冲突条目。Grype 扫目录时，`--vex` 实测没有生效（产品写成 purl、`/src`、`dir:/src` 三种都试过），回灌只能用 Trivy 演示。

## 修复预演

s05（PyYAML）和 s15（lodash）带了 `verify.json`，`fix` 在 `docker run --network none` 的沙箱里分两步跑：装有洞的版本跑攻击脚本，期望 `EXPLOITED`；装修复版本再跑攻击和项目自测，期望 `BLOCKED` + `pass`。两步都符合才生成补丁。

## 实测踩坑

- 问答原文里带着 Log4Shell 的攻击载荷 `${jndi:ldap://...}`，原样作为查询词发出时被网关 WAF 拦截。现在查询词先清洗掉载荷和 URL，搜索失败时降级为“无搜索结果”继续运行。
- 漏洞描述里的函数不一定是你的代码会调用的入口，例如 Jinja2 沙箱漏洞的问题出在模板内部。现在情报卡要求写出应用侧的入口 API。
- 漏洞的前提条件太松会误报，太严会漏报。现在分成两类：能从代码、配置、依赖清单看出来的必须成立；运行环境类的按攻击者有利处理。
