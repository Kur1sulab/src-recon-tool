# recon-desktop —— src-recon-tool 桌面壳（Go）

把现有 Python 侦察流水线包成一个桌面应用：`go build` 一把出单个 `recon-desktop.exe`，
应用本体（HTTP 服务 / 进程管理 / WebView2 壳）全是 Go，运行时零 node 依赖；
扫描引擎仍是既有 `python src/recon.py <子命令>`，由 Go 以子进程方式管理。

## 构建

环境要求：Go ≥ 1.24（本机在 `C:/Go/go/bin/go.exe`），WebView2 Runtime（Win10/11 一般自带）。

```bash
cd desktop-go
C:/Go/go/bin/go.exe build -o recon-desktop.exe .      # 单文件 exe，免安装
```

## 运行

```bash
recon-desktop.exe            # 桌面壳：起 127.0.0.1 本地服务 + WebView2 窗口
recon-desktop.exe --dev      # 开发模式：不起壳，只起本地服务并打印 DEV_URL
recon-desktop.exe --port 8123
```

- 本地服务**只绑 127.0.0.1**，数据面不对外网开放；所有响应 no-store。
- 任务数据落 `%LOCALAPPDATA%\recon-desktop\`（`tasks.json` / `logs\` / `progress\` / `window.json`）。
- 扫描产物仍在仓库根 `out\<目标>\`，与命令行用法完全一致。
- 解释器解析顺序：设置（`RECON_PYTHON` 环境变量）> PATH 上的 `python`。
  子进程自动注入 `PYTHONUTF8=1`、`PYTHONIOENCODING=utf-8`。

## 本地接口（六接口）

| 方法 | 路径 | 说明 |
|---|---|---|
| GET | `/api/env` | 解释器自检（found/path/version/deps_ok）、out 目录、mock 靶站在位、白名单 |
| POST | `/api/scans` | 建任务 `{target,cmd,args?}`；目标必须命中白名单，名单外 403；`args` 里出现目标旗标（-u/--url/-t/--target/-d/--domain/-i/--ip）即 400，目标只能来自受控注入 |
| GET | `/api/scans` | 任务列表 |
| GET | `/api/scans/{id}` | 详情：状态/退出码/进度事件/产物清单/日志尾 |
| POST | `/api/scans/{id}/stop` | 停止（taskkill /T /F 杀进程树） |
| GET | `/api/scans/{id}/evidence` | 证据包 zip：优先现成 evidence-*.zip，否则现打聚合 |

### 本机边界（Host/Origin 校验）

服务只绑 127.0.0.1，请求层再复核一层：

- **Host** 只认 `127.0.0.1` / `localhost` / `[::1]`，其他 Host 一律 403（封本机 DNS rebinding 的读取面）；
- **Origin** 头一旦出现，必须与 Host 同源，否则 403（封本机任意网页用 no-cors 简单请求盲打起停扫描）。

### 授权白名单（硬校验）

只允许三个目标，名单外一律 403：

- `xycovo.com`（自有域名）
- `47.100.49.228`（自有服务器）
- `127.0.0.1:8799`（本机 mock 靶站 `tests/mock_server.py`，端口必须对上）

## 端到端自测（全程离线）

```bash
python tests/mock_server.py 8799          # 仓库根起 mock 靶站
cd desktop-go && recon-desktop.exe --dev --port 8791
# 另开终端：
curl -s http://127.0.0.1:8791/api/env
curl -s -X POST http://127.0.0.1:8791/api/scans -d '{"target":"http://127.0.0.1:8799/real","cmd":"api"}'
curl -s http://127.0.0.1:8791/api/scans/<id>       # 看 progress 四事件 + artifacts
curl -s -o ev.zip http://127.0.0.1:8791/api/scans/<id>/evidence
```

注意：不要对 mock 靶站跑 `all` 全流程（其 IP 分支会外联反查/备案接口）；
mock 验收一律用单模块子命令（api / paths / fingerprint / jsintel）。

## 测试

```bash
cd desktop-go
C:/Go/go/bin/go.exe test ./...     # whitelist 表驱动 / engine 进度解析+假进程起停 / httptest 六接口
```

## 目录结构

```
desktop-go/
  main.go            壳入口：--dev/--port、仓库根定位、退出顺序（停服务→杀进程树→存窗口）
  desktop.go         窗口尺寸记忆(window.json)、单实例互斥、原生消息框
  frontend/          前端三件套（无构建链，go:embed 直接打进 exe）
  internal/whitelist/  正点名单硬校验
  internal/store/      任务持久化（tasks.json，原子写）
  internal/engine/     recon.py 子进程管理 + 进度 JSONL 游标解析 + 进程树终止
  internal/server/     六接口 + 前端静态服务（仅 127.0.0.1）
```

## 进度事件契约（与 Python 引擎）

`src/recon.py --progress-file <jsonl>` 逐行落：
`{"ts":float,"event":"pipeline_start|start|done|fail|pipeline_end","module":str,"detail":str}`
Go 侧游标增量读取；进程退出但没等到 `pipeline_end` 时兜底补一条 fail，界面不挂空。
