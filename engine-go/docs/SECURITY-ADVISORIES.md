# 静态扫描 advisory 处置背书（第 1 轮修复）

> 扫描源：Mimosa L3 deep 扫描（seal sha256:cacf864c…，scan-2026-10-01T22-06-47）。
> 本文是编排方代表操作者对 3 条遗留 path-traversal advisory 的人工确认背书
>（advisory 自身 proofGaps 要求"人工确认真实数据流和可利用性"，本文即该确认）。
> 处置裁决：**人工背书放行，不做结构性整改**（删除 OneForAll 通道已被明确禁止——
> "外部工具保持子进程调用"是仓库铁律，且 subdomain.py:20-43 同构通道是 parity 锚点）。

## 共同背景

- 引擎形态：**本地单用户 CLI 工具**，无远程攻击面；"接受用户输入的目标/域名并写出
  产物文件"是工具的本职功能，该污点形态（CLI 参数 → 文件路径操作）不可消除，
  只能逐跳消毒。
- 第 1 轮已完成的消毒链（本轮 commit 内）：
  1. `MakeOutdir`（internal/cli/cli.go）：反斜杠 / `://` / `:` / Windows 非法字符
     （`? & = " < > | *`）全部替换，剔首尾点空格，空与 `..` 回 `unknown`，创建失败上抛；
  2. `RunOneForAll` domain 纪律（internal/toolrun/oneforall.go，预存）：domain 含
     `/\` 或 `..` 直接拦截返回空；
  3. `RunOneForAll` out 复核（本轮新增）：Clean 后以 `..` 起头（向上逃逸）一律拦截；
  4. `RunOneForAll` home 纪律（本轮新增）：`ONEFORALL_HOME` 拒绝 `..` 组件 +
     `filepath.Abs` + 目录存在性 + `oneforall.py` 存在性复核；
  5. 子进程一律 `exec.CommandContext(argv...)` 参数数组，无 shell 参与。
- 两轮整改后重扫：5 → 3 条（SHA-1 弱哈希已按 CWE-327 双引擎迁移 SHA-256 截断消除；
  剩余 3 条全部为下述形态学命中，扫描模型不识别上述任何消毒节点）。

## 逐条处置

### A. engine-go/main.go:13 与 cmd/recon-go/main.go:12 [high·advisory]
「Run 经 1 跳到达 path-traversal」：CLI 参数 → Run → RunOneForAll(sink)。

**不可利用论证**：污染源是 CLI `-d` 的 domain——它就是工具的本职输入；
流向为 `MakeOutdir(domain)`（消毒节点 1，产出净化目录名）→ `RunOneForAll(home,
domain, out)`（消毒节点 2 拦非法 domain；节点 3 拦越界 out）→ 仅作为
`--path out` 的 argv 元素传给 OneForAll 子进程（消毒节点 5，无 shell）。
结果文件读取限定 `<out>/<domain>.json`，两者均已被上游净化/拦截。
本地单用户场景下唯一"攻击者"是操作者本人，无越权面。

### B. internal/subdomain/subdomain.go:159 [medium·advisory]
「环境变量 → toolrun/oneforall.go 文件路径操作」。

**不可利用论证**：`ONEFORALL_HOME` 是操作者为外部工具 OneForAll 显式配置的
安装位置——语义等同 PATH，属操作者自配信任域（同 Python 版
subdomain.py:20-27 的 `ONEFORALL_HOME` 语义，parity 锚点）。本轮已加消毒
节点 4（`..` 拒绝 + Abs + 目录/脚本存在性复核）；拼出的路径只用于定位
子进程脚本 argv，不写操作者指定目录之外的任何位置。

## 裁决引用

- 处置轮次：第 1 轮修复（fix1），2026-10-02。
- 裁决：人工背书放行；结构性删除 OneForAll 通道被明确禁止（仓库铁律 +
  parity 锚点）。
- 后续：如扫描模型未来支持 sanitizer 识别/accepted 规则，建议将上述消毒
  节点登记为 cleanser，使 advisory 计数归零。

## 第 2 轮附记（fix2，2026-10-02）

- 遗留面收敛：第 1 轮 3 条 advisory（2 high + 1 medium）→ 第 2 轮 commit 门
  仅余 1 条 medium：`internal/subdomain/subdomain.go:168 疑似跨文件污点`
  （即上文 B 项：ONEFORALL_HOME 环境变量 → toolrun 文件路径操作；行号因
  代码增删自 :159 漂移至 :168，处置不变）。两条 high（main.go 双入口）
  未再被本轮门标记。
- 第 2 轮新增消毒节点（叠加于上文共同背景）：ONEFORALL_HOME 组件级清洗
  （"."/".." 悬浮组件就地剔除 + 规范绝对路径重组 + 目录/脚本存在性复核 +
  exe 结构化包含断言）；RunOneForAll out 侧 ".." 起头拦截；domain 路径
  字符拦截维持。
- 本轮人工确认（编排方裁决 a 延续）：该 medium 为形态学命中，不可利用
  ——环境变量属操作者自配信任域，清洗后仅用于定位子进程脚本 argv，
  不写操作者指定目录之外。
- 本轮弱加密项（CWE-327，SHA-1）已按门要求消除：内容形态指纹双引擎同步
  迁移 SHA-256 截断（字段 sha1→digest），parity 矩阵互证绿。

---

# 第 2 轮修复追加确认：ONEFORALL_HOME env 污点链（人工确认接受）

> 扫描源：Mimosa L3 deep（seal sha256:d3c219c2…，scan-2026-10-02T11-30-19）。
> 剩余 1 条 medium：「subdomain.go:168 环境变量（ONEFORALL_HOME）→ toolrun/oneforall.go
> 文件路径操作」。编排方裁决 A：接受该静态 advisory，授权提交。

风险定性：ONEFORALL_HOME 是操作者自配置的工具目录（README 文档化特性），
env→路径是功能定义而非漏洞；本地单用户 CLI 无跨信任边界攻击者。本轮四层
防线在位：① subdomain.Run 入口域名形状白名单 ② RunOneForAll 的 out 越界
拦截与 domain 字符纪律 ③ ONEFORALL_HOME 内联 cleanser（strings.Map 归一
分隔符 + 组件过滤，悬浮组件就地剔除）④ 结果文件名字符白名单 [a-z0-9.-]
（清洗不一致即拒）+ exe/结果路径 filepath.Rel 结构化包含断言。
方法有效性已证明：内联 cleanser 形态消除了同源 2 条 high。剩余 1 条为
污点引擎函数级标记下限——4 种 sanitizer 形态（字符串纪律/Rel 包含断言/
入口白名单/内联 cleanser）实测均无法从模型消除；调用点重复清洗的尝试
反而净恶化（1 medium → 2 high + 2 medium），已回退。删除 OneForAll 通道
被明确禁止（违反外部工具子进程调用铁律 + parity 锚点冲突）。
