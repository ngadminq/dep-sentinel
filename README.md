# dep-sentinel：依赖漏洞分诊

扫描器一次报几十上百条依赖漏洞，真正需要今天动手的往往只有几条。dep-sentinel 回答的就是“哪几条今天修”：

- 已经在用 Trivy / Grype：把 JSON 报告交给它，按代码里是否真的调用、是否已被在野利用重新定级，输出 OpenVEX 回灌给扫描器压噪，CI 只在有“今天修”时报红；
- 没有扫描器：指向一个代码目录，它自己找出所有项目和用到的库，每天巡检，只在出现新的紧急问题时 @ 负责人；
- 群里有人转来一篇漏洞文章问“我们有没有事”，它直接回答影响哪些项目；
- 对标红的条目，在断网沙箱里先打一遍攻击、升级后再打一遍，证明修复有效才生成补丁。

只依赖 Python 3.11+ 标准库。大模型可以换成任何 OpenAI 兼容接口，联网搜索用的是元宝 SearchPro；两者都不配时，用 `--mode static` 也能跑，只是少了“读懂代码和文字”这一层。

## 怎么定级

```
资产清单   lockfile / package.json / requirements*.txt / pom.xml / node_modules / 虚拟环境 / jar 内 pom.properties
候选匹配   OSV 版本比对 + CISA KEV（已在野利用）+ EPSS（利用概率）
情报卡     大模型规划查询 → 联网搜索 → 抽取“漏洞函数、应用侧入口、触发条件、利用证据”
证据核验   引文必须逐字出现在搜索原文里；漏洞库自己点名的函数不能被删掉
可达性     在源码里找 import 和漏洞函数调用，得到 文件:行号
可达研判   大模型看调用上下文判断输入是否外部可控，独立采样 3 次投票
证据门     规则定级：🔴 今天修 / 🟡 本周 / ⚪ 记录；大模型只提供证据，不能单独把一条告警标红
```

🔴 的条件：恶意包；或代码在用且 CISA KEV 已收录；或调用了漏洞函数且有利用信号（KEV、EPSS ≥ 0.1、两个以上独立网站报道利用或 PoC）。

它能认出扫描器常漏掉的依赖：没有 lockfile 的 `package.json`、被改名后拷进项目的 jar、只有虚拟环境没有 requirements 的 Python 项目；代码里 import 了却哪里都没声明的库会单独提醒。

## 安装

```bash
pip install git+https://github.com/ngadminq/dep-sentinel.git
dep-sentinel --help
```

或者用 Docker（镜像里带着录制数据，可以离线复现评测）：

```bash
git clone https://github.com/ngadminq/dep-sentinel.git && cd dep-sentinel
cp .env.example .env
docker compose build
```

不安装也能在仓库里直接跑：`python -m sentinel <命令>`。

## 五个命令

| 命令 | 做什么 | 常用写法 |
|---|---|---|
| `triage` | 读 Trivy / Grype 的 JSON 报告，挑出今天修的，输出 OpenVEX | `dep-sentinel triage trivy.json --root . --fail-on-red` |
| `scan` | 不用扫描器，直接扫一个或几个项目 | `dep-sentinel scan ./order-service ./web --mode full` |
| `patrol` | 自动发现目录下所有项目，和上次结果比，只报变化 | `dep-sentinel patrol /srv/code --send` |
| `ask` | 回答群里转来的漏洞文章“我们有没有事” | `dep-sentinel ask "fastjson 又爆了，我们哪个服务用了？" --repos /srv/code/*` |
| `fix` | 沙箱里预演修复，有效才生成补丁 | `dep-sentinel fix ./order-service` |

各命令都有 `--mode`：`full`（默认，需要大模型和搜索）、`static`（只用漏洞库、KEV、EPSS 和源码检索）；`scan`、`triage`、`fix` 还支持 `osv`（漏洞库原样，做对照用）。

### triage：接在扫描器后面

```bash
trivy fs --scanners vuln --format json --output trivy.json .
dep-sentinel triage trivy.json --root . --fail-on-red
```

Grype 的报告（`grype dir:. -o json`）用法一样，程序会自动认出是哪一种。输出在 `out/triage/`（`--out` 可改）：

- `<tool>.triage.json`：每个项目的定级、理由、调用位置、证据来源；扫描器没报、自己认出的条目单独计数；
- `vex/<项目>.vex.json`：按项目分开的 OpenVEX，扫哪个项目就用哪一份（`trivy fs --vex ...`）；
- `<tool>.vex.json`：合并版，只保留各项目之间没有冲突的 `not_affected`。OpenVEX 用 purl 认包、不区分项目，A 项目判“不受影响”、B 项目判“今天修”的条目不进合并版，否则会把 B 也隐藏掉。

VEX 只把“仅开发依赖、声明了没用到”标成 `not_affected`；大模型判“打不到”的只标 `under_investigation`，扫描器不会隐藏，要人确认。

`--fail-on-red`：有今天修的条目时以 1 退出，扫描器原来的报告照常保留。

用 Docker 时，报告挂到 `/reports`、代码挂到 `/repos`、输出挂到 `/out`：

```bash
docker run --rm --env-file .env -v $PWD:/repos:ro -v $PWD/reports:/reports:ro -v $PWD/out:/out \
  dep-sentinel:0.1 triage /reports/trivy.json --fail-on-red
```

### patrol：每天巡检

```bash
dep-sentinel patrol /srv/code            # 首次体检，只打印
dep-sentinel patrol /srv/code --send     # 推送钉钉
```

结果存在 `state.json`，第二天只推送“新出现的今天修、从本周升级成今天修、已修复”这几类变化，没有变化的日子不发消息。用 Docker 常驻：

```bash
REPOS_DIR=/srv/code docker compose up -d watch    # 按 SCAN_INTERVAL 每天巡检一次
```

### fix：修复预演

`fix` 需要项目里有一份 `verify.json`，写明攻击脚本和自测脚本（放在项目的 `.verify/` 目录，可达性扫描不会读到它们）：

```json
{
 "ecosystem": "npm", "package": "lodash", "cve": "CVE-2019-10744",
 "vulnerable_version": "4.17.11", "fixed_version": "4.17.21",
 "attack": "attack.js", "test": "selftest.js",
 "expect": {"vulnerable": "EXPLOITED", "fixed": "BLOCKED", "test_fixed": "pass"}
}
```

目前支持 npm 和 PyPI。本机有沙箱镜像时，两步都在 `docker run --network none` 里跑，否则退回本机执行。沙箱里不联网，要预演的两个版本先下载到 `sandbox/vendor`（npm 用 `npm pack`，PyPI 用 `pip download`），再构建镜像：

```bash
docker build -f sandbox/node.Dockerfile -t dep-sentinel-sandbox-node:0.1 sandbox
docker build -f sandbox/py.Dockerfile -t dep-sentinel-sandbox-py:0.1 sandbox
```

攻击脚本只做无害标记（写一个文件、污染一个属性）。补丁是 `git apply` 能直接用的 unified diff。例子见 `scenarios/s05-pyyaml-upload` 和 `scenarios/s15-lodash-merge`。

## 接进 CI

`examples/ci/` 里有现成的配置：

- [GitHub Actions](examples/ci/github-actions.yml)：Trivy 扫描 → `triage --fail-on-red` → 上传分诊结果和 VEX；
- [GitLab CI](examples/ci/gitlab-ci.yml)：同样的流程，结果作为 artifacts 保留。

没有配置大模型时，示例里用的是 `--mode static`；把 `LLM_BASE_URL`、`LLM_MODEL`、`LLM_API_KEY`、`YUANBAO_API_KEY` 配成 CI 密钥后改成 `--mode full`。

## 项目配置

在每个项目根目录放一个 `.sentinel.json`（可选）：

```json
{"name": "order-service", "owner": {"name": "张三", "mobile": "13800000000"}, "exposure": "internet"}
```

- `owner`：要 @ 的负责人。不写时取 CODEOWNERS，再不行取最近 90 天提交最多的人（那样只显示名字、无法真正 @）。
- `exposure`：`internet`（对外开放）或 `internal`（只在内网），作为定级依据之一。

## 环境变量

| 变量 | 作用 |
|---|---|
| `LLM_BASE_URL` / `LLM_MODEL` / `LLM_API_KEY` | OpenAI 兼容接口（vLLM、SGLang、Ollama、混元、DeepSeek 等），地址写到 `/v1`；访问内网地址时自动绕过 HTTP 代理 |
| `LLM_REASONING_EFFORT` | 可选，`low` / `medium` / `high`，模型支持时生效 |
| `YUANBAO_API_KEY` | 元宝 SearchPro 联网搜索 |
| `DINGTALK_WEBHOOK` / `DINGTALK_SECRET` | 钉钉自定义机器人；留空则只打印不发送 |
| `SENTINEL_CACHE` | 调用缓存目录。仓库里直接跑时默认 `data/cache`，pip 安装后默认 `~/.cache/dep-sentinel` |
| `SENTINEL_STATE` | 巡检状态文件，默认在缓存目录旁的 `state.json` |
| `SENTINEL_OFFLINE` | 设为 `1` 时只读缓存、不联网，用来回放录制数据 |
| `SENTINEL_SANDBOX_BACKEND` | 强制修复预演用 `docker` 或 `local` |
| `SANDBOX_TIMEOUT` | 单步预演超时秒数，默认 300 |
| `SCAN_INTERVAL` / `REPOS_DIR` | Docker `watch` 模式的巡检间隔和挂载目录 |

## 绑定钉钉

1. 群设置 → 机器人 → 添加机器人 → 自定义（通过 Webhook 接入）。
2. 安全设置勾选“加签”，复制以 `SEC` 开头的密钥。不要选“自定义关键词”，否则消息里不含关键词时会被拒收。
3. 把 Webhook 地址和密钥写进 `DINGTALK_WEBHOOK`、`DINGTALK_SECRET`。
4. 跑一次 `dep-sentinel patrol <目录> --send`，群里收到“首次体检”就绑定成功。

每天只发一条汇总，不会触发钉钉每分钟 20 条的限流。

## 效果

15 个内置场景、120 条原始告警，漏洞库原样告警标红 50 条、场景通过 5/15；完整模式标红 14 条、场景通过 15/15，群聊问答 4/4。不用大模型的 static 模式是 11/15。场景说明、扫描器对照、十个月巡检回放和踩坑记录见 [docs/BENCHMARK.md](docs/BENCHMARK.md)，全部可以离线复现：

```bash
docker compose run --rm eval eval --offline
```

## 已知局限

- 可达性靠正则检索源码，看不到反射和动态 import，所以“没找到调用”只会降到 🟡，不会降到 ⚪。
- 间接依赖没有做调用链分析，只能按“在用”处理。
- 运行时（Dockerfile 里的 node、python 镜像版本）目前只登记，不参与 OSV 比对。
- 支持的生态目前是 npm、PyPI、Maven。
- Grype 扫目录时 `--vex` 实测没有生效，VEX 回灌目前只在 Trivy 上验证过。

## 许可

MIT
