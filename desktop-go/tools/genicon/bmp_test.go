package main

import (
	"bytes"
	"encoding/binary"
	"image"
	"image/color"
	"testing"
)

func solidImg(sz int, c color.RGBA) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, sz, sz))
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			img.SetNRGBA(x, y, color.NRGBA{R: c.R, G: c.G, B: c.B, A: c.A})
		}
	}
	return img
}

func TestEncodeBMPFrameHeader(t *testing.T) {
	const sz = 8
	dib, err := encodeBMPFrame(solidImg(sz, color.RGBA{R: 0x3c, G: 0xb8, B: 0xa8, A: 0xff}))
	if err != nil {
		t.Fatalf("encodeBMPFrame: %v", err)
	}
	if binary.LittleEndian.Uint32(dib[0:4]) != 40 {
		t.Error("biSize 要 40（BITMAPINFOHEADER）")
	}
	if w := int32(binary.LittleEndian.Uint32(dib[4:8])); w != sz {
		t.Errorf("biWidth = %d, 要 %d", w, sz)
	}
	// ICO 规范：DIB 的 biHeight 是"像素高 + 掩码高"= 2×边长
	if h := int32(binary.LittleEndian.Uint32(dib[8:12])); h != 2*sz {
		t.Errorf("biHeight = %d, 要 %d（双高约定）", h, 2*sz)
	}
	if binary.LittleEndian.Uint16(dib[12:14]) != 1 {
		t.Error("biPlanes = 要 1")
	}
	if binary.LittleEndian.Uint16(dib[14:16]) != 32 {
		t.Error("biBitCount = 要 32（BGRA 直通 alpha）")
	}
	if binary.LittleEndian.Uint32(dib[16:20]) != 0 {
		t.Error("biCompression = 要 0（BI_RGB）")
	}

	maskRow := ((sz + 31) / 32) * 4
	wantLen := 40 + sz*sz*4 + maskRow*sz
	if len(dib) != wantLen {
		t.Errorf("DIB 总长 = %d, 要 %d（头+像素+AND 掩码）", len(dib), wantLen)
	}
}

func TestEncodeBMPFrameBottomUpAndMask(t *testing.T) {
	const sz = 4
	img := image.NewNRGBA(image.Rect(0, 0, sz, sz))
	// 第一行（顶行）红、最后一行（底行）蓝，其余黑
	for x := 0; x < sz; x++ {
		img.SetNRGBA(x, 0, color.NRGBA{R: 0xff, A: 0xff})
		img.SetNRGBA(x, sz-1, color.NRGBA{B: 0xff, A: 0xff})
	}
	dib, err := encodeBMPFrame(img)
	if err != nil {
		t.Fatalf("encodeBMPFrame: %v", err)
	}
	px := dib[40:]
	// 自底向上：数据第一行 = 图像最后一行 = 蓝
	if px[0] != 0xff || px[1] != 0x00 || px[2] != 0x00 || px[3] != 0xff {
		t.Errorf("首行首像素 BGRA = % X, 要蓝 FF 00 00 FF（自底向上）", px[0:4])
	}
	// 数据最后一行 = 图像第一行 = 红
	last := px[(sz-1)*sz*4:]
	if last[2] != 0xff || last[0] != 0x00 {
		t.Errorf("末行首像素 BGRA = % X, 要红 00 00 FF FF", last[0:4])
	}
	// alpha 直通：第二行像素的 alpha 字节应为 0（黑透明）
	if a := px[sz*4+3]; a != 0 {
		t.Errorf("透明像素 alpha = %d, 要 0", a)
	}
	// AND 掩码全 0（交由 alpha 通道表态）
	maskRow := ((sz + 31) / 32) * 4
	mask := px[sz*sz*4 : sz*sz*4+maskRow*sz]
	for i, b := range mask {
		if b != 0 {
			t.Fatalf("AND 掩码[%d] = %d, 要全 0", i, b)
		}
	}
}

func TestBuildEntriesFormatLayout(t *testing.T) {
	entries := buildEntries()
	// 全档生成；≤128 BMP、仅 256 PNG（LoadImage/GDI 只可靠解 BMP 帧）
	if len(entries) != len(iconSizes) {
		t.Fatalf("条目数 = %d, 要 %d", len(entries), len(iconSizes))
	}
	for _, e := range entries {
		if e.Size <= 128 {
			if e.BMP == nil || e.PNG != nil {
				t.Errorf("%dpx 应为 BMP 帧", e.Size)
			}
			if len(e.BMP) < 40 {
				t.Errorf("%dpx BMP 数据过短", e.Size)
			}
		} else {
			if e.PNG == nil || e.BMP != nil {
				t.Errorf("%dpx 应为 PNG 帧", e.Size)
			}
			if !bytes.HasPrefix(e.PNG, []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}) {
				t.Errorf("%dpx 缺 PNG 签名", e.Size)
			}
		}
	}
}
