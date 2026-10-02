package cli

// fix2_cli_test.go — 第 2 轮审计+对抗修复回归（cli），全部离线：
//   1. MakeOutdir Windows 保留设备名主干（对抗实测 report -t CON 真建 out\CON）
//   2. 重复旗标 last-wins（argparse 语义；audit low#7：此前 first-non-default 相反）
//   3. reverse -i 严格 IP 校验（对抗实测 '8.8.8.8&x=1' 照单全收拼数据源 URL）
//   4. icp -d 域名形状校验（注入形态入口拒绝）

import (
	"flag"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeOutdirDefusesReservedStems(t *testing.T) {
	t.Chdir(t.TempDir())
	outRoot, _ := filepath.Abs("out")
	cases := map[string]string{
		"CON": "CON_", "nul": "nul_", "Com1.zip": "Com1_.zip",
		"lpt9": "lpt9_", "con.txt": "con_.txt", "config.com": "config.com",
	}
	for target, want := range cases {
		got, err := MakeOutdir(target)
		if err != nil {
			t.Fatalf("MakeOutdir(%q): %v", target, err)
		}
		if base := filepath.Base(got); base != want {
			t.Fatalf("MakeOutdir(%q) 目录名 = %q, want %q", target, base, want)
		}
		if abs, _ := filepath.Abs(got); !strings.HasPrefix(abs, outRoot+string(filepath.Separator)) {
			t.Fatalf("[%q] 目录越出 out/: %s", target, abs)
		}
	}
}

func TestPickAliasLastWins(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	d := fs.String("d", "", "")
	domain := fs.String("domain", "", "")
	// 模拟 `--domain a.com -d b.com`：短旗标后写 → last-wins 取 b.com
	args := []string{"--domain", "a.com", "-d", "b.com"}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if got := pickAliasLastWins(args, map[string]*string{"-d": d, "--domain": domain}); got != "b.com" {
		t.Fatalf("last-wins 应取 b.com, 得 %q", got)
	}
	// 翻转顺序：`-d b.com --domain a.com` → a.com
	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	d2 := fs2.String("d", "", "")
	domain2 := fs2.String("domain", "", "")
	args2 := []string{"-d", "b.com", "--domain", "a.com"}
	_ = fs2.Parse(args2)
	if got := pickAliasLastWins(args2, map[string]*string{"-d": d2, "--domain": domain2}); got != "a.com" {
		t.Fatalf("last-wins 应取 a.com, 得 %q", got)
	}
	// 全部未设置 → ""
	fs3 := flag.NewFlagSet("t3", flag.ContinueOnError)
	d3 := fs3.String("d", "", "")
	domain3 := fs3.String("domain", "", "")
	_ = fs3.Parse(nil)
	if got := pickAliasLastWins(nil, map[string]*string{"-d": d3, "--domain": domain3}); got != "" {
		t.Fatalf("未设置应得空串, 得 %q", got)
	}
}

func TestPickIntAliasLastWins(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	w := fs.Int("w", 8, "")
	workers := fs.Int("workers", 8, "")
	args := []string{"-w", "16", "--workers", "8"}
	if err := fs.Parse(args); err != nil {
		t.Fatal(err)
	}
	if got := pickIntAliasLastWins(args, 8, map[string]*int{"-w": w, "--workers": workers}); got != 8 {
		t.Fatalf("`-w 16 --workers 8` last-wins 应得 8, 得 %d", got)
	}
	fs2 := flag.NewFlagSet("t2", flag.ContinueOnError)
	w2 := fs2.Int("w", 8, "")
	workers2 := fs2.Int("workers", 8, "")
	_ = fs2.Parse(nil)
	if got := pickIntAliasLastWins(nil, 8, map[string]*int{"-w": w2, "--workers": workers2}); got != 8 {
		t.Fatalf("未设置应回默认 8, 得 %d", got)
	}
}

func TestReverseRejectsNonIP(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, bad := range []string{"8.8.8.8&x=1", "example.com", "1.2.3.4/24", " 1.2.3.4", ""} {
		if code := Run([]string{"reverse", "-i", bad}); code != 2 {
			t.Fatalf("reverse -i %q 应 exit 2, 得 %d", bad, code)
		}
	}
}

func TestICPRejectsBadDomainShape(t *testing.T) {
	t.Chdir(t.TempDir())
	for _, bad := range []string{"../evil", "a&key=x", "a b.com", "a..com"} {
		if code := Run([]string{"icp", "-d", bad}); code != 2 {
			t.Fatalf("icp -d %q 应 exit 2, 得 %d", bad, code)
		}
	}
}
