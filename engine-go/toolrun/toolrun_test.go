package toolrun

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// TestParseOneForAllJSON 钉死 NDJSON 解析语义：尾逗号、前导点、空值、脏行、去重排序。
func TestParseOneForAllJSON(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "example.com.json")
	content := "{\"subdomain\": \"a.example.com\"},\n" +
		"{ \"subdomain\" : \".dev.example.com\" },\n" +
		"not-a-json,\n" +
		"{\"subdomain\": \"\"},\n" +
		"{\"subdomain\": \"a.example.com\"},\n" +
		"{\"other\": 1},\n"
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	got := parseOneForAllJSON(p)
	want := []string{"a.example.com", "dev.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("parse = %v, want %v", got, want)
	}
}

func TestRunOneForAllMissingHome(t *testing.T) {
	if got := RunOneForAll("", "x.com", t.TempDir(), 0); got != nil {
		t.Fatalf("home 为空应返回空: %v", got)
	}
	if got := RunOneForAll(t.TempDir(), "x.com", t.TempDir(), 0); got != nil {
		t.Fatalf("oneforall.py 不存在应返回空: %v", got)
	}
}

// TestFindSubfinderAbsent 可选通道语义：缺席返回 ""，不报错。
func TestFindSubfinderAbsent(t *testing.T) {
	p := FindSubfinder()
	if p != "" {
		t.Skipf("本机存在 subfinder（%s），缺席语义由注入桩覆盖", p)
	}
}

func TestRunSubfinderEmptyPath(t *testing.T) {
	subs, err := RunSubfinder("", "x.com", 0)
	if err != nil || subs != nil {
		t.Fatalf("path 为空应 (nil, nil): %v %v", subs, err)
	}
}
