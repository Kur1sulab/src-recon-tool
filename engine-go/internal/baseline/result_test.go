package baseline

// result_test.go — 统一包络 schema 冻结测试（桌面 baselineview 渲染契约）。
// 包络字段：{check,target,url,generated_at,conclusion{level,text},risks[],data,error}。
// 键名与形态一经冻结不得漂移：桌面线按本 schema 渲染，双边对测试不对实现。

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestResultEnvelopeJSON(t *testing.T) {
	r := Result{
		Check:       "secheaders",
		Target:      "example.test",
		URL:         "https://example.test",
		GeneratedAt: "2026-10-06T12:00:00+08:00",
		Conclusion:  Conclusion{Level: LevelWarn, Text: "缺失 2 个安全头"},
		Risks:       []Risk{{Level: LevelWarn, Title: "未设置 Content-Security-Policy"}},
		Data:        map[string]any{"missing_count": 2},
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, key := range []string{
		`"check":"secheaders"`, `"target":"example.test"`, `"url":"https://example.test"`,
		`"generated_at":"2026-10-06T12:00:00+08:00"`,
		`"conclusion":{"level":"warn","text":"缺失 2 个安全头"}`,
		`"risks":[{`, `"level":"warn"`, `"title":"未设置 Content-Security-Policy"`,
		`"data":{"missing_count":2}`,
	} {
		if !strings.Contains(s, key) {
			t.Errorf("包络缺键/漂移: %s\n实际: %s", key, s)
		}
	}
	// error 空 → omitempty 不输出（桌面「缺文件=未运行 / error 非空=失败态」语义）
	if strings.Contains(s, `"error"`) {
		t.Errorf("error 为空时不应输出: %s", s)
	}
	// error 非空 → 输出
	r.Error = "DNS 查询全部失败"
	b, _ = json.Marshal(r)
	if !strings.Contains(string(b), `"error":"DNS 查询全部失败"`) {
		t.Errorf("error 非空应输出: %s", b)
	}
}

func TestNewResultEmptyCollections(t *testing.T) {
	// risks/data 为空时序列化必须是 []/{}（非 null），桌面渲染契约
	r := NewResult("webfiles", "example.test", "https://example.test")
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), `"risks":[]`) {
		t.Errorf("risks 空应为 []: %s", b)
	}
	if !strings.Contains(string(b), `"data":{}`) {
		t.Errorf("data 空应为 {}: %s", b)
	}
	if r.Check != "webfiles" || r.Target != "example.test" || r.GeneratedAt == "" {
		t.Errorf("NewResult 未填基础字段: %+v", r)
	}
}

func TestLevelConstants(t *testing.T) {
	// 四级色条契约（桌面 level→ColOkBg·ColWarnBg·ColErrBg 族映射）
	if LevelOK != "ok" || LevelWarn != "warn" || LevelFail != "fail" || LevelInfo != "info" {
		t.Errorf("level 常量漂移: %s %s %s %s", LevelOK, LevelWarn, LevelFail, LevelInfo)
	}
}
