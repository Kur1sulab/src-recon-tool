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
C:/Go/go/bin/go.exe build -o recon-go.exe .    # 零第三方依赖（stdlib-only）
C:/Go/go/bin/go.exe test ./...                  # 全部单测 + Python↔Go parity
```

- Go 1.24+；本仓库零第三方依赖，无需联网拉模块。
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
| `llm -d` | `modules.llm_assist` | ❌ **不移植，弃用**（可选增强，跑 `llm` 会提示并 exit 2） |
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
- **urlcheck（SSRF 边界）**：默认阻断 Python 3.8 `is_private/is_loopback/
  is_link_local/is_reserved` 全集——Go 标准库 `net.IP.IsPrivate` 只有 RFC1918，
  缺 198.18.0.0/15（Clash fake-ip 段）等 14 段，必须自实现；授权内网目标由调用方
  显式 `allowPrivate=true` 放行。私网表有动态 python 探针单测逐 IP 对照。
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
`recon-go llm` 会打印弃用提示并 exit 2。需要该功能请继续使用 Python 版。
