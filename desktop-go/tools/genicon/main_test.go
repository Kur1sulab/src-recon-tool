package main

import (
	"image"
	"image/color"
	"testing"
)

func near(a, b uint8, tol uint8) bool {
	d := int(a) - int(b)
	if d < 0 {
		d = -d
	}
	return d <= int(tol)
}

func sameColor(c, want color.NRGBA, tol uint8) bool {
	return near(c.R, want.R, tol) && near(c.G, want.G, tol) && near(c.B, want.B, tol)
}

func TestPaintSonarBoundsAndColors(t *testing.T) {
	const sz = 128
	img := paintSonar(sz)
	if b := img.Bounds(); b.Dx() != sz || b.Dy() != sz {
		t.Fatalf("bounds = %v, 要 %dx%d", b, sz, sz)
	}

	// 四角在圆角砖外 → 全透明
	for _, p := range []image.Point{{0, 0}, {sz - 1, 0}, {0, sz - 1}, {sz - 1, sz - 1}} {
		if c := img.NRGBAAt(p.X, p.Y); c.A != 0 {
			t.Errorf("角点(%d,%d) alpha = %d, 要 0", p.X, p.Y, c.A)
		}
	}

	// 中心点是亮青（accent-hi #74d6c7）
	c := img.NRGBAAt(sz/2, sz/2)
	if c.A == 0 {
		t.Fatal("中心点透明, 要亮青实心")
	}
	if !sameColor(c, color.NRGBA{R: 0x74, G: 0xd6, B: 0xc7, A: 0xff}, 40) {
		t.Errorf("中心色 = %v, 要接近 #74d6c7", c)
	}

	// 砖底是石板（chrome #101820）——取环外、刻度外的点（对角 0.18 位置）
	// viewBox24: 点 (4.5, 19.5) 在砖内、环（r8.3）外、刻度外
	f := func(u float64) int { return int(u / 24 * sz) }
	base := img.NRGBAAt(f(4.5), f(19.5))
	if base.A != 0xff {
		t.Errorf("砖底 alpha = %d, 要 255", base.A)
	}
	if !sameColor(base, color.NRGBA{R: 0x10, G: 0x18, B: 0x20, A: 0xff}, 24) {
		t.Errorf("砖底色 = %v, 要接近 #101820", base)
	}

	// 环上有品牌青（#3cb8a8）——viewBox24: (12, 4.3) 落在环带（3.7–5.3）
	ring := img.NRGBAAt(f(12), f(4.3))
	if !sameColor(ring, color.NRGBA{R: 0x3c, G: 0xb8, B: 0xa8, A: 0xff}, 48) {
		t.Errorf("环色 = %v, 要接近 #3cb8a8", ring)
	}
}

func TestIconSizes(t *testing.T) {
	if len(iconSizes) < 5 {
		t.Fatalf("iconSizes = %v, 至少 5 档多尺寸", iconSizes)
	}
	has := func(want int) bool {
		for _, s := range iconSizes {
			if s == want {
				return true
			}
		}
		return false
	}
	if !has(16) || !has(256) {
		t.Errorf("iconSizes = %v, 必须含最小 16 与最大 256", iconSizes)
	}
	for _, s := range iconSizes {
		if s < 16 || s > 256 {
			t.Errorf("iconSizes 含越界档 %d（16–256）", s)
		}
	}
}
