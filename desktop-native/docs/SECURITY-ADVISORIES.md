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

## ADV-20261004-02 壳被硬杀 → 扫描进程孤儿（已修复入账）

- **发现**：对抗轮 P2 实锤——壳（recon-native.exe）被任务管理器结束/崩溃时，
  扫描子进程变孤儿继续对目标发包。复刻实验：按 runner.go 执行模式起
  cmd→ping 树，taskkill /F 硬杀父进程后 PING.EXE 存活，谱系指向已死父链；
  代码佐证：runner.go killTree 仅按需逐树杀、StopAll 只挂优雅 DestroyEvent
  路径、全仓无 Job Object。
- **修复**：`internal/engine/job_windows.go`——Start 起进程即挂 Windows
  Job Object（JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE），壳无论优雅退出还是被
  硬杀，句柄随进程回收而关闭，Job 内整树（含 python 起的子进程）同步终局；
  Stop/StopAll/monitor 收尾均关句柄，killTree 保留为兜底与非 Windows 路径
  （job_other.go 空实现）。挂载失败（宿主 Job 限制）不阻断起扫描。
- **回归**：`internal/engine/job_windows_test.go` TestJobObjectKillsTreeOnClose
  ——真 cmd→ping 树挂 Job，关句柄后 tasklist 全局 PING.EXE 存量归零。
- **状态**：已修复（2026-10-04 终修轮），非残留风险。

