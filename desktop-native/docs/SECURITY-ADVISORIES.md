# desktop-native 安全 advisory 台账（人工背书）

> 纪律来源：Mimosa 中危须「向用户说明风险并取得确认」，此类语义自设计
> 数据流按夜班先例记台账随提交、禁止结构性删除。引擎线（engine-go/）
> 的同类条目记其自家台账 `engine-go/docs/SECURITY-ADVISORIES.md`，不在本册。

## ADV-20261004-01 RECON_PYTHON 跨文件污点（medium，by-design 背书）

- **扫描器定位**：`internal/ui/app.go:131` 「疑似跨文件污点」。
- **数据流**：环境变量 `RECON_PYTHON` → `NewSession()`（internal/ui/session.go）→
  `Runner.pythonPath` → `ResolvePython()` → `exec.Command(python, src/recon.py, …)`
  子进程执行。
- **为什么是设计而非漏洞**：解释器路径是本机用户显式配置（环境变量或设置页
  「保存并生效」，session.go 落配置文件），与 desktop-go 壳 `main.go:64` 的
  `engine.NewRunner(repoRoot, dataDir, os.Getenv("RECON_PYTHON"))` 逐字同构，
  后者已经过 desktop-go 两轮审计在案。扫描目标侧另有正点白名单硬闸
  （internal/whitelist，名单外 403/拒绝），污点汇的执行参数（目标）不受
  该路径影响。
- **何种条件下升级为真问题**：若未来引入「远端可写的配置源」或「网页内容
  可改写 RECON_PYTHON/设置页持久化值」的通道，此流即成外部可控执行点，
  届时必须在 SetPythonPath 入口加路径存在性与可执行性校验并重评。
- **背书**：用户（编排方）2026-10-04 原生轮修复会话确认按 by-design 记账。
