package engine

// allrunner.go — all 模块的进程内编排器：按 src/recon.py cmd_all（:123-171）
// 两分支直调 engine-go 公开函数。
//
//	域名分支：subdomain → verify → asset → icp(非致命) → PickBase →
//	          fingerprint → paths → api → [jsintel/portscan skipped] → report
//	IP 分支： reverse → icp(反查域名≤5 个循环，非致命) → PickBase(反查首域名)
//	          → fingerprint → api → [portscan/jsintel skipped] → report
//
// 步骤事件与 python _run_step（recon.py:46-60）同构：start/done/fail(module)；
// fatal 步骤失败即中止流水线（pipeline_end fail），非致命步骤降级继续。
// jsintel/portscan 未随全集成版移植，对应步骤发 skipped 事件（不中断）。
// 取消传播：每步骤间设 ctx 检查点，引擎调用全部走 *Context 变体
//（FetchOpt.Ctx 贯穿，Stop 即时生效）。

import (
	"context"
	"fmt"

	"github.com/Kur1sulab/src-recon-tool/engine-go/apiunauth"
	"github.com/Kur1sulab/src-recon-tool/engine-go/asset"
	"github.com/Kur1sulab/src-recon-tool/engine-go/cli"
	"github.com/Kur1sulab/src-recon-tool/engine-go/fingerprint"
	"github.com/Kur1sulab/src-recon-tool/engine-go/icp"
	"github.com/Kur1sulab/src-recon-tool/engine-go/paths"
	"github.com/Kur1sulab/src-recon-tool/engine-go/report"
	"github.com/Kur1sulab/src-recon-tool/engine-go/reverseip"
	"github.com/Kur1sulab/src-recon-tool/engine-go/subdomain"
)

// skippedDetail 退役步骤的 skipped 事件文案（inproc_integration_test 钉住）。
const skippedDetail = "未随全集成版提供"

// allStep 单步执行（_run_step 同构）：start → fn → done | fail(module, err)。
// fatal=false 时失败降级为 nil（不阻断主流程，语义同 python fatal=False）。
func (r *Runner) allStep(ctx context.Context, id, module string, fatal bool, fn func() error) error {
	if err := ctx.Err(); err != nil { // 循环检查点：停止后不再起新步骤
		return err
	}
	r.emit(id, module, "start", "")
	err := fn()
	switch {
	case err != nil:
		r.emit(id, module, "fail", err.Error())
		if fatal {
			return err
		}
		return nil
	case ctx.Err() != nil: // 步骤中途被停：已发生的失败/完成照实记录，外层收敛
		return ctx.Err()
	default:
		r.emit(id, module, "done", "")
		return nil
	}
}

// runAllModule all 模块入口（模块表注册项）。extra 在 ValidateExtraArgs 层
// 已保证为空（all 无可选项）。
func (r *Runner) runAllModule(ctx context.Context, id, target string, extra []string) error {
	out, err := r.makeOutDir(target)
	if err != nil {
		return fmt.Errorf("输出目录创建失败: %w", err)
	}
	if cli.IsIP(target) {
		err = r.allIPBranch(ctx, id, target, out)
	} else {
		err = r.allDomainBranch(ctx, id, target, out)
	}
	if err != nil {
		return err
	}
	// 收尾报告（两分支共用，fatal）：聚合资产档案 + 证据包
	return r.allStep(ctx, id, "report", true, func() error {
		if report.RunReportContext(ctx, out, target) == "" {
			return fmt.Errorf("report.md 写盘失败")
		}
		return nil
	})
}

// allDomainBranch 域名分支（recon.py:158-173）。
func (r *Runner) allDomainBranch(ctx context.Context, id, target, out string) error {
	if err := r.allStep(ctx, id, "subdomain", true, func() error {
		_, err := subdomain.RunContext(ctx, target, out)
		return err
	}); err != nil {
		return err
	}
	// 审计补充（recon.py:162）：证书日志含大量失效域名，必须验证存活
	if err := r.allStep(ctx, id, "verify", true, func() error {
		subdomain.RunVerifyContext(ctx, out, 8, true)
		return nil
	}); err != nil {
		return err
	}
	if err := r.allStep(ctx, id, "asset", true, func() error {
		asset.RunAssetContext(ctx, target, out)
		return nil
	}); err != nil {
		return err
	}
	if err := r.allStep(ctx, id, "icp", false, func() error {
		icp.RunICPContext(ctx, target, out)
		return nil
	}); err != nil {
		return err
	}
	base := r.pickBase(target)
	return r.allWebSteps(ctx, id, base, out, true, "jsintel", "portscan")
}

// allIPBranch IP 分支（recon.py:129-154）：反查域名 → 逐个 ICP（≤5 个，避免
// 限频）→ 指纹/API。裸 IP 常被按域名路由的站点返回 404，优先用反查出的
// 首个域名作为探测入口（recon.py:143-145 同策略）。
func (r *Runner) allIPBranch(ctx context.Context, id, target, out string) error {
	var doms []string
	if err := r.allStep(ctx, id, "reverse", true, func() error {
		doms = reverseip.RunReverseContext(ctx, target, out)
		return nil
	}); err != nil {
		return err
	}
	if err := r.allStep(ctx, id, "icp", false, func() error {
		for i, d := range doms {
			if i >= 5 { // 备案查询最多查 5 个，避免限频
				break
			}
			icp.RunICPContext(ctx, d, out)
		}
		return nil
	}); err != nil {
		return err
	}
	host := target
	if len(doms) > 0 {
		host = doms[0]
	}
	base := r.pickBase(host)
	return r.allWebSteps(ctx, id, base, out, false, "portscan", "jsintel")
}

// allWebSteps 两分支共用尾段：PickBase 入口 → fingerprint →（域名分支含
// paths）→ api → 两个退役步骤 skipped。顺序保持 recon.py 各分支原序：
// 域名分支 fingerprint→paths→api→jsintel→portscan（:166-173），
// IP 分支 fingerprint→api→portscan→jsintel（:148-154）。
func (r *Runner) allWebSteps(ctx context.Context, id, base, out string, withPaths bool, skipA, skipB string) error {
	if err := r.allStep(ctx, id, "fingerprint", true, func() error {
		fingerprint.RunFingerprintContext(ctx, base, out)
		return nil
	}); err != nil {
		return err
	}
	if withPaths {
		if err := r.allStep(ctx, id, "paths", true, func() error {
			_, err := paths.RunPathsContext(ctx, base, out)
			return err
		}); err != nil {
			return err
		}
	}
	if err := r.allStep(ctx, id, "api", true, func() error {
		_, err := apiunauth.RunAPIContext(ctx, base, out, true)
		return err
	}); err != nil {
		return err
	}
	for _, m := range []string{skipA, skipB} {
		if err := ctx.Err(); err != nil {
			return err
		}
		r.emit(id, m, "skipped", skippedDetail)
	}
	return nil
}
