# src-recon-tool

![tests](https://github.com/Kur1sulab/src-recon-tool/actions/workflows/tests.yml/badge.svg)

SRC 漏洞挖掘信息收集自动化工具（Python）。将子域枚举、资产测绘、指纹识别、
敏感路径探测与 YAML 化 POC 验证编排为一条流水线，单次全流程约 30 分钟内完成。

> ⚠️ 仅限授权范围内的安全测试使用。禁止用于未授权目标。

## 功能模块

| 模块 | 说明 |
|---|---|
| subdomain | OneForAll 子域枚举（未配置时自动降级证书日志查询：crt.sh → certspotter 兜底，均无需 key）；`--verify` 可做 **DNS 解析 + HTTP 探活**，把失效域名滤掉 |
| asset | FOFA / Hunter 资产测绘（API key 走环境变量，未配置自动跳过） |
| **reverse** | **IP 反查域名**（hackertarget 免 key；裸 IP 侦察的第一步） |
| **icp** | **ICP 备案查询**（域名 → 备案号 / 主办单位 / 类型 / 审核日期；apihz 接口，可用 APIHZ_ID/APIHZ_KEY 覆盖 demo 额度） |
| fingerprint | 内置常用指纹规则（ThinkPHP/Shiro/Spring/WordPress/Nginx/Tomcat/Actuator/Nacos/Jenkins/Grafana/Elasticsearch 等，headers+body 双通道） |
| paths | 敏感路径探测（.git/.env/swagger/actuator/druid 等；**软 404 基线过滤 + 存活复验**，SPA/WAF 站点不再满屏假存活） |
| **api** | **API 文档暴露 / 未授权探测**（27 个候选端点：Swagger/OpenAPI、Actuator、Druid、GraphQL、Eureka/Nacos/Consul、pprof、heapdump…**软 404 基线过滤 + 命中后存活复验**；存活命中自动进入**取证模式**：落盘响应片段 + 可直接复跑的 curl 复现稿） |
| **jsintel** | **JS 情报提取**（前端接口挖掘：抓目标页 + 外链 JS（并发 ≤6 / 单文件 ≤2MB / 只 GET），提取 ① API 端点线索——规范化去重、滤静态资源，绝对 URL 可直接喂给 api/paths 复核；② 敏感线索——key/secret/token/password/appid… 只标文件+行号+片段，**值打码（只留前 4 位）**；③ 域名线索——子域/第三方域/内网 IP 归类。WAF/异常站点优雅降级，线索≠漏洞需人工复核） |
| **portscan** | **端口扫描**（纯标准库 TCP connect，零三方依赖：内置 ~100 常用端口表，`--ports 80,443,8000-8100` 混合写法自定义；并发 ≤32 / 连接超时 1.5s 可调；开放端口做 1s 轻量旗帜抓取并识别服务名（SSH/Redis/MySQL/…）。**仅限授权目标**） |
| poc | YAML 化 POC 模板引擎（nuclei 风格子集，status/contains matcher，and/or 条件） |
| **report** | **资产档案 + 证据包**（把所有模块产出聚合成 `report.md`：归属线索/子域存活/指纹/敏感路径/API 暴露 + 待人工跟进；并把 `evidence/` 打成 zip 随提交稿交付；`all` 自动生成） |
| ~~llm~~ | **已弃用**：需向第三方服务发送扫描数据，为守住数据不出本机的红线整体移除（Python 与 Go 引擎同步） |

## 架构

```
target → recon.py → subdomain / asset / fingerprint / paths / jsintel / portscan → out/<target>/
                                              ↓
                                       poc_engine（YAML 模板）
                                              ↓
```

## 安装

```bash
pip install -r requirements.txt
# OneForAll 需单独部署，路径经环境变量 ONEFORALL_HOME 指定（可选）
```

## Go 引擎（engine-go/）

同一套引擎的纯 Go 重写（`recon-go` 单文件、零外网测试、Python↔Go parity 全量对齐），
子命令与 `python src/recon.py` 一一对齐。详见 `engine-go/README.md`、
`docs/PARITY.md`（双引擎对照）与 `docs/TEST-PORT.md`（测试平移清点）。

```bash
# 构建（Go 1.24+；仅在拉取 yaml.v3 时需代理）
cd engine-go
GOPROXY=https://goproxy.cn,direct C:/Go/go/bin/go.exe build -o recon-go.exe ./cmd/recon-go
C:/Go/go/bin/go.exe test ./...        # 全部单测 + Python↔Go parity（python 缺失时 parity 自动 skip）

# 用法（子命令与 Python 版同名同参）
./recon-go.exe subdomain -d example.com --verify
./recon-go.exe api -u https://example.com          # 含取证模式
./recon-go.exe report -t example.com               # 资产档案 + 证据包
# ...其余子命令见 ./recon-go.exe（无参数打印对照 help）
```

**已实现（✅）**：subdomain / verify / fingerprint / asset / reverse / icp / api /
paths / poc / report。**未实现**：`all`（一键全流程，exit 2 并提示——全流程请用
Python 版 `python src/recon.py all`）；jsintel / portscan 暂不移植（拍板留档，
exit 2 防静默走错）。**llm 弃用**：两侧同步（Python 侧 llm_assist.py 已整体移除、
recon.py 仅留弃用提示；Go 侧同行为——提示后 exit 2）。

## 用法

```bash
export FOFA_EMAIL=... FOFA_KEY=... HUNTER_KEY=...   # Windows: setx
python src/recon.py all -d example.com        # 域名全流程
python src/recon.py all -t 47.100.49.228      # IP 全流程：反查域名 → ICP → 指纹 → API 探测
python src/recon.py subdomain -d example.com  # 仅子域
python src/recon.py subdomain -d example.com --verify   # 子域 + 存活验证（DNS/HTTP）
python src/recon.py verify -d example.com     # 对已有 subdomains.txt 做存活验证
python src/recon.py asset -d example.com      # 仅资产测绘
python src/recon.py reverse -i 47.100.49.228  # 仅 IP 反查域名
python src/recon.py icp -d example.com        # 仅 ICP 备案查询
python src/recon.py api -u https://example.com        # 仅 API 文档/未授权探测
python src/recon.py jsintel -u https://example.com    # 仅 JS 情报提取（端点/敏感线索/域名）
python src/recon.py portscan -t 47.100.49.228         # 仅端口扫描（默认常用端口表，仅限授权目标）
python src/recon.py portscan -t 127.0.0.1 --ports 80,443,8000-8100 --timeout 1   # 自定义端口/超时
python src/recon.py fingerprint -u https://example.com
python src/recon.py paths -u https://example.com
python src/recon.py poc -t https://example.com -p pocs/example-http-detect.yaml
python src/recon.py report -t example.com     # 按已有产出重新生成资产档案 + 证据包
```

`all` 跑完会自动生成 `out/<目标>/report.md`（资产档案）与 `out/<目标>/evidence-<目标>-<时间>.zip`（证据包，仅在有过存活取证时）。

`all` 的 `-t/--target` 同时接受**域名或 IP**（自动识别）：给 IP 时走
`反查域名 → 逐个 ICP 备案 → 用反查到的域名做指纹/API 探测`（裸 IP 直连常被按域名路由的站点返回 404）。

无任何 API key 时，`all` 全流程仍可跑通：子域走 crt.sh（挂掉自动切 certspotter）、
备案走 apihz 公开接口，其余模块自动降级跳过。

`all` 已接入 jsintel 与 portscan（同样**优雅降级**，失败只打 `[!]` 警告不阻断主流程）：
域名目标在 API 探测后自动做 **JS 情报提取**（以探测 base 为入口）与**常用端口扫描**；
IP 目标对裸 IP 扫端口、对探测入口抓 JS。产物落在同一 `out/<目标>/` 目录
（`jsintel.json/txt`、`ports.json/txt`），并进入 `report.md` 的「JS 线索」「开放端口」章节。

## POC 模板示例

```yaml
id: example-admin-detect
info:
  name: Admin Panel Detect
  severity: info
requests:
  - method: GET
    path: "/admin"
    matchers:
      - type: status
        status: [200, 401, 403]
```

## llm 模块弃用声明

`llm` 模块（LLM 辅助解读）已**整体移除**：它会把子域/资产/指纹/敏感路径打包
POST 到第三方 LLM 服务（如 `LLM_BASE_URL` 指向的外部 API），与「扫描数据不出
本机」的形态红线冲突。Python 版 `recon.py all` 不再调用该步骤，`recon.py llm`
打印弃用提示并以退出码 2 结束（与 Go 版 `recon-go llm` 行为一致）；
`modules/llm_assist.py` 已删除。

## 效果

多源并行 + 模板化后，单次信息收集从约 2 小时压缩至 30 分钟内；
已用于 EDUSRC 授权范围内的实战挖洞。

## 质量与审计

- **测试**：`python -m unittest discover -s tests` —— 65 项，含**可控靶站集成测试**
  （`tests/mock_server.py` 模拟 SPA 软 404 / JSON catch-all / 全局 403 / 统一跳转 / JS 线索站等陷阱场景）
- **审计报告**：[docs/audit-20260924.md](docs/audit-20260924.md) —— 对探测模块做对抗性审计：
  修复"无软 404 基线"（SPA 站点曾 19 条全部假存活）与"命中不复验存活"两个严重问题，
  修复后**假阳性归零、真阳性零损失**，并固化为 CI 回归测试。
- **三轮自审累计修复**：软 404 基线 ✗、命中不复验 ✗、判定过宽 ✗、目录穿越 ✗、全局超时污染 ✗、
  报告内联脏数据 ✗ —— 每一轮都留了回归测试。

## 目录

```
src/recon.py            CLI 入口
src/modules/            各功能模块
pocs/                   YAML POC 模板
tests/                  单元测试
out/                    输出目录（gitignore）
```

## License

MIT
