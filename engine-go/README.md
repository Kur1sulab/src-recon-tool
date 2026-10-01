# recon-go —— src-recon-tool 的 Go 引擎

把 Python 引擎（`src/recon.py` + `src/modules/`）按「语义忠实优先」移植到纯 Go，
产出**单文件** `recon-go.exe`，CLI 子命令与 `python src/recon.py` 一一对齐。

**移植边界（铁律）**：只有引擎自身的编排逻辑被重写（HTTP 数据源 / 软 404 基线 /
存活验证 / 指纹匹配 / 输出解析 / 去重合并 / 安全落盘）；外部工具一律保持子进程
调用、不重写——OneForAll（Python）仍是子域枚举主通道，subfinder（Go 二进制）
只作可选补充通道（存在才用）。

## 构建

```bash
cd engine-go
C:/Go/go/bin/go.exe build -o recon-go.exe ./cmd/recon-go   # 标准布局入口（推荐）
C:/Go/go/bin/go.exe build -o recon-go.exe .                # 根目录兼容入口，二进制等价
C:/Go/go/bin/go.exe test ./...                              # 全部单测 + Python↔Go parity
```

- Go 1.24+；本仓库零第三方依赖，无需联网拉模块。
- 入口逻辑在 `internal/cli`，`cmd/recon-go/main.go` 与根 `main.go` 是两个等价薄壳。
- `go test` 全程零外网：crt.sh/certspotter 打 httptest stub，OneForAll 走
  `testdata/oneforall_fake.py.txt` fixture，subfinder 用注入桩。

## 子命令对照表（14 个，对齐 recon.py:137-212）

| 子命令 | Python 对应 | Go 版状态 |
|---|---|---|
| `subdomain -d <domain> [--verify]` | `modules.subdomain.run_subdomain` | ✅ c1 已实现 |
| `verify -d <domain> [-w 8]` | `modules.subdomain.run_verify` | ✅ c1 已实现 |
| `fingerprint -u <url>` | `modules.fingerprint.run_fingerprint` | ✅ c1 已实现 |
| `all -t <domain\|ip>` | `cmd_all` | ⏳ c2 轮（已注册，exit 2 防静默走错） |
| `asset -d` | `modules.asset` | ⏳ c2 轮（已注册） |
| `reverse -i <ip>` | `modules.reverse_ip` | ⏳ c2 轮（已注册） |
| `icp -d` | `modules.icp` | ⏳ c2 轮（已注册） |
| `api -u` | `modules.api_unauth` | ⏳ c2 轮（已注册） |
| `paths -u` | `modules.paths` | ⏳ c2 轮（已注册） |
| `jsintel -u` | `modules.jsintel` | ⏳ c2 前拍板是否纳入（该模块只在本地未推提交里） |
| `portscan -t` | `modules.portscan` | ⏳ 同上 |
| `poc -t -p` | `modules.poc_engine`（YAML 引擎） | ⏳ c2 轮（已注册，届时引入 yaml.v3） |
| `llm -d` | ~~`modules.llm_assist`~~ | ❌ **不移植，弃用**（Python 版也已整体移除该模块，两侧行为一致：提示并 exit 2） |
| `report -t` | `modules.report` | ⏳ c3 轮（已注册） |

未实现命令打印「第 N 轮实现」并 exit 2；无参数打印 help 并 exit 1——**绝不静默
走错分支**。

## 目录结构

```
engine-go/
├── main.go                  # 14 子命令分发表 + is_ip/make_outdir/pick_base
├── internal/netutil/        # fetch（HTTP 底座）/ urlcheck（SSRF 边界）/
│                            # safeio（安全落盘）/ baseline（软404/存活复验）
├── internal/toolrun/        # 外部工具子进程适配层（OneForAll 主 / subfinder 可选）
├── internal/subdomain/      # 子域枚举（OneForAll→subfinder→crt.sh→certspotter）
│                            # + 存活验证（DNS 全量 + HTTP 探活前 120）
├── internal/fingerprint/    # 28 条指纹规则逐字移植（header/body 双通道）
├── internal/mockweb/        # httptest 靶站：与 tests/mock_server.py 逐字节对齐
├── internal/parity/         # Python↔Go parity 测试基建 + 断言矩阵
└── testdata/                # OneForAll fixture（.txt 后缀合规）
```

## 关键语义（与 Python 逐字段对齐，parity 测试钉死）

- **fetch**：协议白名单 http/https；先按 max_bytes 截断再算指纹（hex 前 16 位）；
  body 是 utf-8 ignore 解码；4xx/5xx 同样算 `ok=true`；重定向最多 10 跳，超限
  返回最后一个 30x（对齐 urllib HTTPError(302) 分支，重定向环 baseline=redirect
  依赖它）；headers 键小写、同键多值后写覆盖。
  **fix1 加固**：① error 字段剥离 `Get "URL": ` 前缀，只留原因文本（query 里
  携带的 token/api_key 等不得经 error 字段进入日志与证据包，对齐 Python
  `str(e)` 形态）；② `FetchOpt.HopCheck` 逐跳校验钩子——入口做过 CheckHTTPURL
  的调用方（fingerprint / pick_base）传入同策略回调，302 落点不再免检（Python
  侧可观测结果一致：解析失败的落点两引擎都按请求失败处理，跨 scheme 重定向
  两侧协议栈都拒绝）。
- **urlcheck（SSRF 边界）**：默认阻断 Python 3.8 `is_private/is_loopback/
  is_link_local/is_reserved` 全集——Go 标准库 `net.IP.IsPrivate` 只有 RFC1918，
  缺 198.18.0.0/15（Clash fake-ip 段）等 14 段，必须自实现；授权内网目标由调用方
  显式 `allowPrivate=true` 放行。私网表有动态 python 探针单测逐 IP 对照。
  **fix1 加固**：crt.sh / certspotter 通道在请求前先过 `CheckHTTPURL(allowPrivate=false)`
  （对齐 Python `_from_crtsh`/`_from_certspotter`），校验失败走「异常降级」——
  0 次重试直接切下一通道（此前 Go 侧无校验且 3 次退避重试，降级耗时/文案与
  Python 漂移）。
- **安全落盘**：文件名白名单 `[A-Za-z0-9._-]`、截 64、剥首尾点号；目录剔 `../`
  与 `.` 组件；最终路径必须仍在 out 内才写盘。**fix1 加固**：Windows 保留设备名
  主干（con/prn/aux/nul/com1-9/lpt1-9，任意扩展名）命中后主干补 `_`（与 Python
  `safe_filename` 同步）。
- **输出目录（make_outdir）**：`://` `/` `\` `:` `?` `&` `=` `"` `<` `>` `|` `*`
  全部换 `_`，再剥首尾点/空格；空与 `..` 回 `unknown`；目录创建失败上抛（CLI
  exit 1，对齐 Python makedirs 抛 OSError 未捕获）。三处实现（Go cli / Python
  recon.py / desktop-go outDirFor）逐字符同规则，两引擎产物目录同名。
- **--progress-file 全局参数（fix1 补齐）**：`recon-go --progress-file <path>
  <子命令> ...`（或 `--progress-file=` 形态、环境变量 `RECON_PROGRESS_FILE` 兜底），
  事件 JSONL 键序 `{ts,event,module,detail}` 与 `recon.py:31-62` 契约一致：
  `pipeline_start → start → done|fail → pipeline_end`（all 无模块级事件；
  help/无子命令/未知子命令不发事件）。桌面壳 Runner 靠它驱动任务状态机。
- **verify 证据包形态（fix1 对齐）**：`subdomains_live.json` 死亡行 `ips:[]`、
  `http:{}`，探活成功行 http 为完整六键对象——与 Python `verify_subs` 落盘形态
  逐键一致（此前 Go 侧 nil slice 序列化为 null、零值探活为六字段空对象）。
- **安全落盘**：文件名白名单 `[A-Za-z0-9._-]`、截 64、剥首尾点号；目录剔 `../`
  与 `.` 组件；最终路径必须仍在 out 内才写盘。
- **软 404 基线**：双随机探针分类 soft404 / uniform403 / redirect / normal /
  unknown；命中必须复验（连续 2 次形态一致且特征仍在才算存活）。
- **parity**：Python 与 Go 引擎打同一个 Go httptest 靶站，断言矩阵覆盖
  baseline 五场景 / fetch 字段 / 指纹命中序列 / HTTPProbe / VerifySubs rows /
  OneForAll 适配器。python 缺席时 parity 自动 skip，不阻塞纯 Go 测试。

## 与 Python 版的已知微差（其余为零）

1. **OneForAll 子进程超时**：Python 侧 `subprocess.TimeoutExpired` 会炸穿调用栈；
   Go 侧打印告警后返回空、继续走降级链（更稳，语义等价于"该通道本次无结果"）。
2. **重定向跟随实现**：Python urllib 逐跳构造请求、Go `net/http` 内建跟随，
   均为最多 10 跳；慢响应下超时语义微差（socket 级 vs 整请求级），parity 按字段
   不按耗时。
3. **subfinder 通道是 Go 侧增强**（Python 版没有）：插在 OneForAll 之后做并集
   补充，存在才用、失败只告警、不改变 Python 原降级链的触发条件。
4. **行尾**：Go 写 LF，Python 在 Windows 写 CRLF；消费方一律按行解析，无影响。
5. **重定向逐跳校验（fix1 起，Go 侧先行）**：Go 的 fingerprint/pick_base 在
   Follow 模式对每个 30x 落点复跑 CheckHTTPURL（同入口策略）；Python urllib
   无逐跳复验（TOCTOU 级已接受风险，见 netutil.py docstring）。当前全部调用
   点 allowPrivate=true，两引擎对一切可解析落点的可观测行为一致；仅当未来
   出现 allow_private=false 的调用方 + 可控重定向时，Go 拒绝、Python 跟随——
   届时须同步给 Python fetch 加同构钩子。

## subfinder 可选通道

存在才用：优先探测 `tools/bin/subfinder.exe`，再查 PATH。缺席时主降级链
（OneForAll → crt.sh → certspotter）行为完全不变。下载（best-effort，可失败）：

```bash
mkdir -p tools/bin
curl -L -o tools/bin/subfinder.zip \
  "https://gh-proxy.com/https://github.com/projectdiscovery/subfinder/releases/latest/download/subfinder_windows_amd64.zip"
# 解压出 subfinder.exe 放 tools/bin/；版本会记录到 tools/bin/VERSIONS.md
```

## 实测白名单红线（务必遵守）

自动化测试只打本机 httptest/mock 靶站。**真实目标实测仅限人工验收**，且只允许：
- `xycovo.com`（用户自有站点）
- `47.100.49.228`（用户自有服务器）
- 本机 `127.0.0.1` mock / httptest 靶站

禁打任何其他真实目标。DNS 锚点一律用 `127.0.0.1` 字面量——Clash fake-ip 环境下
假域名会"解析成功"（198.18.0.0/15），禁止依赖 NXDOMAIN 断言。

## llm 模块弃用声明

`llm` 子命令（`modules.llm_assist`，LLM 辅助解读）在 Go 版**不移植**：属可选
增强、依赖外部 LLM 接口，与"纯 Go 单文件、零外网依赖"的引擎定位冲突。执行
`recon-go llm` 会打印弃用提示并 exit 2。Python 版已同步移除该模块（`modules/llm_assist.py` 已删除，`recon.py llm` 同样提示并 exit 2）——该功能需要向第三方服务发送扫描数据，与数据不出本机的红线冲突，两侧都不再提供。
