package ico

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// pngBlob 造一段带 PNG 签名的假图数据（容器层不解析 PNG 内容，只校验签名与搬运）。
func pngBlob(seed byte, n int) []byte {
	b := make([]byte, n)
	copy(b, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A})
	for i := 8; i < n; i++ {
		b[i] = seed + byte(i)
	}
	return b
}

func TestEncodeParseRoundTrip(t *testing.T) {
	in := []Entry{
		{Size: 16, PNG: pngBlob(1, 300)},
		{Size: 32, PNG: pngBlob(2, 500)},
		{Size: 256, PNG: pngBlob(3, 1000)},
	}
	data, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// ICONDIR：reserved=0、type=1（图标）、count=条目数
	if len(data) < 6 {
		t.Fatalf("数据过短: %d", len(data))
	}
	if got := binary.LittleEndian.Uint16(data[0:2]); got != 0 {
		t.Errorf("reserved = %d, 要 0", got)
	}
	if got := binary.LittleEndian.Uint16(data[2:4]); got != 1 {
		t.Errorf("type = %d, 要 1（图标）", got)
	}
	if got := binary.LittleEndian.Uint16(data[4:6]); got != 3 {
		t.Errorf("count = %d, 要 3", got)
	}

	out, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(out) != len(in) {
		t.Fatalf("Parse 条目数 = %d, 要 %d", len(out), len(in))
	}
	for i := range in {
		if out[i].Size != in[i].Size {
			t.Errorf("条目 %d size = %d, 要 %d", i, out[i].Size, in[i].Size)
		}
		if !bytes.Equal(out[i].PNG, in[i].PNG) {
			t.Errorf("条目 %d PNG 数据不一致", i)
		}
	}
}

func TestParseDirEntryLayout(t *testing.T) {
	// 逐字段核对 ICONDIRENTRY（16 字节）：宽高字节（256 记 0）、planes=1、bitCount=32
	in := []Entry{
		{Size: 16, PNG: pngBlob(1, 300)},
		{Size: 256, PNG: pngBlob(2, 400)},
	}
	data, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	e0 := data[6:22]
	if e0[0] != 16 || e0[1] != 16 {
		t.Errorf("16px 条目宽高字节 = %d/%d, 要 16/16", e0[0], e0[1])
	}
	if got := binary.LittleEndian.Uint16(e0[4:6]); got != 1 {
		t.Errorf("planes = %d, 要 1", got)
	}
	if got := binary.LittleEndian.Uint16(e0[6:8]); got != 32 {
		t.Errorf("bitCount = %d, 要 32", got)
	}
	// 第一张图紧跟目录：6 + 2*16 = 38
	if got := binary.LittleEndian.Uint32(e0[12:16]); got != 38 {
		t.Errorf("imageOffset = %d, 要 38", got)
	}
	// 256px 条目宽高字节记 0
	e1 := data[22:38]
	if e1[0] != 0 || e1[1] != 0 {
		t.Errorf("256px 条目宽高字节 = %d/%d, 要 0/0（256 约定）", e1[0], e1[1])
	}
	// 第二张图偏移 = 38 + 第一张长度
	if got := binary.LittleEndian.Uint32(e1[12:16]); got != 38+300 {
		t.Errorf("第二张 imageOffset = %d, 要 %d", got, 38+300)
	}
	// 图数据本体带 PNG 签名
	if !bytes.HasPrefix(data[38:], []byte{0x89, 'P', 'N', 'G'}) {
		t.Error("第一张图数据缺 PNG 签名")
	}
}

func TestEncodeBMPPassthrough(t *testing.T) {
	// BMP(DIB) 帧不含 PNG 签名，容器层必须原样放行（LoadImage/GDI 只可靠解 BMP 帧）
	bmp := make([]byte, 64) // 伪 DIB 数据
	for i := range bmp {
		bmp[i] = byte(i)
	}
	in := []Entry{{Size: 32, BMP: bmp}}
	data, err := Encode(in)
	if err != nil {
		t.Fatalf("Encode(BMP): %v", err)
	}
	out, err := Parse(data)
	if err != nil {
		t.Fatalf("Parse(BMP): %v", err)
	}
	if len(out) != 1 || out[0].Size != 32 {
		t.Fatalf("回读条目错: %+v", out)
	}
	if !bytes.Equal(out[0].BMP, bmp) {
		t.Error("BMP 数据回读不一致")
	}
	if out[0].PNG != nil {
		t.Error("BMP 条目不应产生 PNG 数据")
	}
}

func TestEncodeRejectsAmbiguousEntry(t *testing.T) {
	if _, err := Encode([]Entry{{Size: 32}}); err == nil {
		t.Error("PNG/BMP 全空: 要报错")
	}
	if _, err := Encode([]Entry{{Size: 32, PNG: pngBlob(1, 100), BMP: make([]byte, 32)}}); err == nil {
		t.Error("PNG/BMP 同时设置: 要报错")
	}
}

func TestEncodeRejectsBadInput(t *testing.T) {
	cases := []struct {
		name string
		in   []Entry
	}{
		{"空条目", nil},
		{"尺寸过小", []Entry{{Size: 0, PNG: pngBlob(1, 100)}}},
		{"尺寸过大", []Entry{{Size: 257, PNG: pngBlob(1, 100)}}},
		{"非 PNG 数据", []Entry{{Size: 32, PNG: []byte("not a png at all....")}}},
		{"PNG 过短", []Entry{{Size: 32, PNG: []byte{0x89, 'P'}}}},
	}
	for _, c := range cases {
		if _, err := Encode(c.in); err == nil {
			t.Errorf("%s: 要报错, 却通过了", c.name)
		}
	}
}

func TestParseRejectsBadData(t *testing.T) {
	cases := []struct {
		name string
		data []byte
	}{
		{"过短", make([]byte, 5)},
		{"类型不对", func() []byte { // type=2（光标）拒收
			b := make([]byte, 6)
			binary.LittleEndian.PutUint16(b[2:], 2)
			binary.LittleEndian.PutUint16(b[4:], 0)
			return b
		}()},
		{"count 超界", func() []byte {
			b := make([]byte, 6)
			binary.LittleEndian.PutUint16(b[4:], 9) // 目录声称 9 条，数据没有
			return b
		}()},
	}
	for _, c := range cases {
		if _, err := Parse(c.data); err == nil {
			t.Errorf("%s: 要报错, 却通过了", c.name)
		}
	}
}
