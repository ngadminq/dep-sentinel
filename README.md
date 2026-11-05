# dep-sentinel：依赖安全值班员

小团队没有安全工程师时，漏洞告警要么没人看，要么多到没人看。dep-sentinel 指向一个代码目录，自己找出里面所有项目和用到的开源库，每天检查一遍，只在**出现新的、真需要今天动手的问题**时 @ 负责人；没有变化的日子不发消息。群里有人转来一篇漏洞文章问“我们有没有事”，它也能直接回答。

它从这些地方认出“用了哪些库、什么版本”，不需要人登记：

- 依赖清单：`package-lock.json`、`package.json`、`requirements*.txt`、`pom.xml`
- 已经装好的库：`node_modules/**/package.json`、虚拟环境里的 `*.dist-info`
- 直接拷进项目的 jar：读 jar 内的 `pom.properties`，文件被改名也认得出真实坐标
- 代码里 import 了、但哪里都没声明的库：单独列出提醒

## 动静结合

```
【静】资产清单   lockfile / pom.xml / requirements*.txt / Dockerfile → 仓库 × 包 × 版本 × 负责人
【静】候选匹配   OSV 版本比对 + CISA KEV（已在野利用）+ EPSS（利用概率）
【动】情报卡     大模型规划查询 → 元宝搜索 → 大模型抽取“漏洞函数、触发条件、利用证据”
【静】证据核验   引文必须逐字出现在搜索原文里、页面必须提到该漏洞；漏洞库自己点名的函数不能被删掉
【静】可达性     在仓库源码里找 import 和漏洞函数调用，得到 文件:行号
【动】可达研判   大模型看调用上下文判断输入是否外部可控，独立采样 3 次投票；“可达”必须引用真实命中行
【静】证据门     规则定级：🔴 今天修 / 🟡 本周 / ⚪ 记录，大模型只提供证据，不能单独把一条告警标红
输出            钉钉消息（@负责人、修复命令） + OpenVEX（Trivy / Grype 可直接读取压噪） + 全量调用记录
```

🔴 的条件：恶意包；或代码在用且 CISA KEV 已收录；或调用了漏洞函数且有利用信号（KEV、EPSS ≥ 0.1、两个以上独立网站报道利用或 PoC）。

## 快速开始

```bash
cp .env.example .env          # 填 LLM_BASE_URL / LLM_MODEL / YUANBAO_API_KEY / DINGTALK_WEBHOOK
docker compose build
docker compose run --rm eval eval --offline   # 不需要任何密钥：回放录制数据，复现全部实验
docker compose run --rm eval eval             # 用你自己的模型和元宝 Key 重跑
docker compose run --rm eval replay --offline # 回放十个月的每日巡检
```

巡检自己的代码（把放代码的目录挂到 `/repos`，里面有几个项目都会自动找出来）：

```bash
# 先跑一次，看首次体检结果（不发钉钉）
docker run --rm --env-file .env -v /path/to/code:/repos:ro -v sentinel-data:/data dep-sentinel:0.1 patrol
# 确认没问题后常驻：每天巡检一次，只推送变化
REPOS_DIR=/path/to/code docker compose up -d watch
# 群里有人转来文章时手动问
docker run --rm --env-file .env -v /path/to/code:/repos:ro dep-sentinel:0.1 ask "fastjson 反序列化漏洞又爆了，我们哪个服务用了？"
```

巡检结果存在 `/data/state.json`，所以 `sentinel-data` 卷要保留：第二天只会推送“新出现的今天修、从本周升级成今天修、已修复”这几类变化。

## 接在 Trivy / Grype 后面

已经在跑扫描器的团队，不用换工具。把扫描器的 JSON 报告交给 `triage`，它只回答“这些条目里哪几条今天修”：

```bash
trivy fs --scanners vuln --format json --output trivy.json /path/to/code
python -m sentinel triage trivy.json --root /path/to/code --fail-on-red
```

Grype 的报告（`grype dir:/path/to/code -o json`）用法一样，程序会自动认出是哪一种。输出在 `out/triage/`：

- `<tool>.triage.json`：每个项目的定级、理由、调用位置、证据来源；
- `vex/<项目>.vex.json`：按项目分开的 OpenVEX，扫哪个项目就用哪一份（`trivy fs --vex ...`）；
- `<tool>.vex.json`：合并版，只保留各项目之间没有冲突的 `not_affected`。OpenVEX 用包的 purl 认产品，不区分项目；如果 A 项目判“不受影响”、B 项目判“今天修”，合并后会把 B 也隐藏掉，所以这类条目不进合并版。

`--fail-on-red`：有今天修的条目时以 1 退出，CI 只在这时报红，扫描器原来的报告照常保留。

扫描器没报、但 dep-sentinel 自己认出来的条目（没有 lockfile 的 `package.json`、改名的 jar、只有虚拟环境的 Python 项目）会单独计数，不会丢掉。

## 绑定钉钉

1. 在钉钉里打开要接收提醒的群 → 右上角“群设置” → “机器人” → “添加机器人” → 选“自定义（通过 Webhook 接入）”。
2. 安全设置勾选“加签”，复制显示的密钥（以 `SEC` 开头）。不要选“自定义关键词”，否则消息里不含关键词时会被拒收。
3. 完成后复制 Webhook 地址（`https://oapi.dingtalk.com/robot/send?access_token=...`）。
4. 写进 `.env`：

   ```bash
   DINGTALK_WEBHOOK=https://oapi.dingtalk.com/robot/send?access_token=你的token
   DINGTALK_SECRET=SEC你的密钥
   ```

5. 要 @ 到具体的人，在每个项目根目录放一个 `.sentinel.json`，写上负责人的钉钉手机号（不写时取 CODEOWNERS，再不行取最近 90 天提交最多的人，但那样只显示名字、无法真正 @）：

   ```json
   {"name": "order-service", "owner": {"name": "张三", "mobile": "13800000000"}, "exposure": "internet"}
   ```

   `exposure` 填 `internet`（对外开放）或 `internal`（只在内网），会作为判断依据之一。
6. 发一条试试：`docker run --rm --env-file .env -v /path/to/code:/repos:ro -v sentinel-data:/data dep-sentinel:0.1 patrol --send`。群里收到“首次体检”消息就绑定成功。

钉钉自定义机器人每分钟最多 20 条，dep-sentinel 每天只发一条汇总，不会触发限流。

不用 Docker 时只需要 Python 3.11+，没有任何第三方依赖：`python eval.py`、`python -m sentinel scan <repo>`。

## 换成你自己的大模型

任何 OpenAI 兼容接口都可以（vLLM、SGLang、Ollama、混元、DeepSeek 等），在 `.env` 里改 `LLM_BASE_URL`（写到 `/v1`）和 `LLM_MODEL`。作者的实验用的是内网部署的 Qwen3.8-27B-FP8。访问内网地址时程序会自动绕过 HTTP 代理。

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

另有 4 个群聊问答（`scenarios/questions.json`），其中两个不带 CVE 编号，要靠大模型和搜索识别组件。

每个场景的期望写在 `scenarios/*/expect.json`，`eval.py` 用三种模式对照：

- `osv`：漏洞库原样告警，HIGH / CRITICAL 视为紧急（相当于常见审计工具的做法）
- `static`：加上 KEV、EPSS、import 检查、从漏洞描述里正则提取函数名、证据门（不用大模型和搜索）
- `full`：再加上大模型和元宝搜索

## 实验结果（2026-11-03，Qwen3.8-27B-FP8 + 元宝 SearchPro）

| 模式 | 场景通过 | 114 条原始告警中标红 | 群聊问答 |
|---|---|---|---|
| osv（漏洞库原样） | 5/14 | 47 | — |
| static（不用大模型） | 10/14 | 8 | 1/4 |
| full（动静结合） | 14/14 | 14 | 4/4 |

- static 失败的地方都需要“读懂代码或文字”：常量模板被误判为可达（s11）、内部固定地址被误判为 SSRF 可达（s09）、jar 里的 fastjson 和 Jinja2 沙箱判不出可达（s13、s14）、不带 CVE 编号的问答。
- full 比 static 多标红 8 条、少标红 2 条，都可复核。多标的每条都有调用行号、投票 3:0（一条 2:1），并且有 EPSS ≥ 0.1 或两个以上独立来源的 PoC。少标的是 s11 的常量模板，以及 log4j 的 CVE-2021-45046：它在 KEV 里，但要改过日志格式才能触发，3 票都判不可达。
- 重复实验：大模型调用重新采样 2 轮，搜索计划沿用。三轮都是 14/14、4/4，标红分别是 14、13、15 条。11 条三轮都标红；6 条时红时黄，多数是摘出的证据网站数在“两个”上下浮动。三轮都没有误标红。
- 11 条稳定标红里有 3 条只靠元宝搜到的公开利用成立，不在 KEV、EPSS 也不高：PyYAML 上传文件、fastjson CVE-2025-70974、Jinja2 CVE-2024-34064。
- 每日巡检回放（`python replay.py`，2026-01-01 至 2026-11-02，12 个项目、109 条告警）：
  - 按 OSV 公开日期，漏洞库这段时间新提醒 76 次，分布在 12 天；
  - dep-sentinel 首日体检报 12 件今天修，之后只在 2026-01-09 找过一次人（legacy-order 的 fastjson CVE-2025-70974）；
  - EPSS 和网页证据用的是今天的值，不是当天的值。
- s01 的期望在首轮后补入 CVE-2021-45105，理由写在 `expect.json` 的 note 里。
- 一次运行约调用大模型 269 次、元宝约 130 次；已被 KEV 收录的漏洞不再搜索。元宝单次调用中位约 2.5 秒。
- 实测踩坑：
  - 问答原文里带着 Log4Shell 的攻击载荷 `${jndi:ldap://...}`，原样作为查询词发出时被网关 WAF 拦截。现在查询词先清洗掉载荷和 URL，搜索失败时降级为“无搜索结果”继续运行。
  - 漏洞描述里的函数不一定是你的代码会调用的入口，例如 Jinja2 沙箱漏洞的问题出在模板内部。现在情报卡要求写出应用侧的入口 API。
  - 漏洞的前提条件太松会误报，太严会漏报。现在分成两类：能从代码、配置、依赖清单看出来的必须成立；运行环境类的按攻击者有利处理。

### 接在扫描器后面（2026-11-05，15 个场景）

两个扫描器扫同一个 `scenarios/` 目录，报告交给 `triage --mode full`：

| 扫描器 | 报告条数（严重 / 高危） | 其中今天修 | 扫描器没报、自己认出（其中今天修） | 合计今天修 |
|---|---|---|---|---|
| Trivy 0.58.1（跳过 Java 库） | 98（7 / 35） | 8 | 24（6） | 14 |
| Grype 0.121.1 | 106（8 / 37） | 12 | 14（2） | 14 |

- 两边合计都是 14 条，和 `eval.py` 完整模式的结果一致。
- 扫描器漏掉的原因：只有 `package.json` 没有 lockfile（s15，两个都没报）；改名的 jar（s13，Trivy 跳过了 Java 库）；只有虚拟环境（s14，`trivy fs` 不读）；投毒包的 MAL- 编号和 NSWG 编号（OSV 和扫描器库收录不一致）。
- 旧版 Grype 0.86.1（数据库 schema 5）只报 39 条，axios 只有 3 条，升级到 0.121.1 后是 33 条。扫描器版本旧，漏报会很多。
- VEX 回灌：Trivy 用 purl 认产品，测试 VEX 把一条 lodash 标成不受影响后，4 个项目里的同一条全被隐藏，所以合并版要去掉冲突条目。Grype 扫目录时，`--vex` 实测没有生效（产品写成 purl、`/src`、`dir:/src` 三种都试过），回灌只能用 Trivy 演示。我们的 VEX 只把“仅开发依赖、声明了没用到”标成 `not_affected`；大模型判“打不到”的只标 `under_investigation`，扫描器不会隐藏，要人确认。

`eval.py` 的输出在 `out/eval/<mode>/`：每个场景一份 JSON（每条告警的判定理由、调用位置、网页证据、被丢弃的引文数、钉钉消息、OpenVEX），以及 `report.md` 汇总表。

## 已知局限

- 可达性靠正则检索源码，看不到反射和动态 import，所以“没找到调用”只会降到 🟡，不会降到 ⚪。
- 间接依赖没有做调用链分析，只能按“在用”处理。
- 运行时（Dockerfile 里的 node、python 镜像版本）目前只登记，不参与 OSV 比对。
