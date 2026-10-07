# desktop-native 安全 advisory 台账（人工背书）

> 纪律来源：Mimosa 中危须「向用户说明风险并取得确认」，此类语义自设计
> 数据流按夜班先例记台账随提交、禁止结构性删除。引擎线（engine-go/）
> 的同类条目记其自家台账 `engine-go/docs/SECURITY-ADVISORIES.md`，不在本册。

## ADV-20261004-01 RECON_PYTHON 跨文件污点（medium，by-design 背书；已随直调重写消解）

- **扫描器定位**：`internal/ui/app.go:131` 「疑似跨文件污点」（2026-10-04 扫描时点）。
- **数据流（原始）**：环境变量 `RECON_PYTHON` → `NewSession()`（internal/ui/session.go）→
  `Runner.pythonPath` → `ResolvePython()` → `exec.Command(python, src/recon.py, …)`
  子进程执行。
- **为什么当时是设计而非漏洞**：解释器路径是本机用户显式配置（环境变量或设置页
  「保存并生效」，session.go 落配置文件），与 desktop-go 壳 `main.go:64` 的
  `engine.NewRunner(repoRoot, dataDir, os.Getenv("RECON_PYTHON"))` 逐字同构，
  后者已经过 desktop-go 两轮审计在案。扫描目标侧另有格式卫生硬闸
  （internal/whitelist），污点汇的执行参数（目标）不受该路径影响。
- **何种条件下曾升级为真问题**：若未来引入「远端可写的配置源」或「网页内容
  可改写 RECON_PYTHON/设置页持久化值」的通道，此流即成外部可控执行点。
- **背书**：用户（编排方）2026-10-04 原生轮修复会话确认按 by-design 记账。
- **消解（2026-10-07 第 2 步直调重写）**：桌面进程内直调 engine-go，子进程壳
  整体退役——app.go 的 `os.Getenv("RECON_PYTHON")` 读取、NewSession 的
  pythonPath 形参、`Runner.ResolvePython/ProbePython` 全部删除，污点源与汇
  双端不存在，本条数据流不复可构成。设置页 Python 卡随之移除。

## ADV-20261004-02 壳被硬杀 → 扫描进程孤儿（已修复入账；修复件已随子进程壳退役）

- **发现**：对抗轮 P2 实锤——壳（recon-native.exe）被任务管理器结束/崩溃时，
  扫描子进程变孤儿继续对目标发包。复刻实验：按 runner.go 执行模式起
  cmd→ping 树，taskkill /F 硬杀父进程后 PING.EXE 存活，谱系指向已死父链；
  代码佐证：runner.go killTree 仅按需逐树杀、StopAll 只挂优雅 DestroyEvent
  路径、全仓无 Job Object。
- **修复（2026-10-04 终修轮）**：`internal/engine/job_windows.go`——Start 起进程
  即挂 Windows Job Object（JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE），壳无论优雅
  退出还是被硬杀，句柄随进程回收而关闭，Job 内整树（含 python 起的子进程）
  同步终局；Stop/StopAll/monitor 收尾均关句柄，killTree 保留为兜底与非
  Windows 路径（job_other.go 空实现）。挂载失败（宿主 Job 限制）不阻断起扫描。
- **回归**：`internal/engine/job_windows_test.go` TestJobObjectKillsTreeOnClose
  ——真 cmd→ping 树挂 Job，关句柄后 tasklist 全局 PING.EXE 存量归零。
- **修复件退役（2026-10-07 第 2 步直调重写）**：job_windows.go/job_other.go/
  killTree/taskkill 随子进程壳整体删除——直调后桌面进程内无壳启动的任何
  子进程，扫描作业与进程同生命周期（进程死则作业死），孤儿化威胁面不复
  存在，无可级联对象。原威胁模型与修复记录保留在本台账作历史留痕。

