// genicon —— 生成应用图标 assets/icon.ico（多尺寸，纯标准库，无外部素材依赖）。
//
// 图形 = index.html 品牌铭牌的声呐签名（viewBox 0 0 24：环 r7.5 描边1.6 +
// 中心点 r2.4 + 四刻度），配色取 frontend/DESIGN.md「Slate Sonar」令牌：
// 石板砖底 chrome #101820、品牌青 #3cb8a8（环/刻度）、亮青 #74d6c7（中心点）。
// 逐子像素超采样抗锯齿，PNG 帧经 internal/ico 打包。
//
// 用法：go run ./tools/genicon -o assets/icon.ico
package main

import (
	"bytes"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"math"
	"os"
	"path/filepath"

	"recon-desktop/internal/ico"
)

// iconSizes 图标尺寸档（16 起步、256 上限，覆盖资源管理器/任务栏/Alt-Tab 各档）。
var iconSizes = []int{16, 24, 32, 48, 64, 128, 256}

// 令牌色（frontend/DESIGN.md，组件层同源）。
var (
	colTile   = color.RGBA{R: 0x10, G: 0x18, B: 0x20, A: 0xff} // chrome 石板砖底
	colRing   = color.RGBA{R: 0x3c, G: 0xb8, B: 0xa8, A: 0xff}             // primary 品牌青（环/刻度）
	colCenter = color.RGBA{R: 0x74, G: 0xd6, B: 0xc7, A: 0xff}            // accent-hi 亮青（中心点）
)

// viewBox 24 坐标系里的声呐几何（与 index.html brand-mark SVG 一致）。
const (
	vb          = 24.0
	cx, cy      = 12.0, 12.0
	ringR       = 7.5  // 环半径
	ringStroke  = 1.6  // 环/刻度描边
	dotR        = 2.4  // 中心点半径
	tileRadius  = 5.4  // 圆角砖圆角（≈22%）
	subsamples  = 4    // 每像素边长的超采样数（4x4=16 子样本）
)

// ticks 四刻度线段（与 SVG M12 1.5v4 等四笔一致，圆帽靠线段距离实现）。
var ticks = [][4]float64{
	{12, 1.5, 12, 5.5},   // 上
	{12, 18.5, 12, 22.5}, // 下
	{1.5, 12, 5.5, 12},   // 左
	{18.5, 12, 22.5, 12}, // 右
}

// sdRoundBox 圆角方砖的符号距离（<0 在砖内）。
func sdRoundBox(px, py, bx, by, r float64) float64 {
	qx := math.Abs(px-bx) - (bx - r)
	qy := math.Abs(py-by) - (by - r)
	ax, ay := math.Max(qx, 0), math.Max(qy, 0)
	return math.Hypot(ax, ay) + math.Min(math.Max(qx, qy), 0) - r
}

// sdSeg 点到线段的距离（圆帽描边=距离≤描边半径）。
func sdSeg(px, py, x1, y1, x2, y2 float64) float64 {
	dx, dy := x2-x1, y2-y1
	l2 := dx*dx + dy*dy
	t := 0.0
	if l2 > 0 {
		t = ((px-x1)*dx + (py-y1)*dy) / l2
		t = math.Min(1, math.Max(0, t))
	}
	return math.Hypot(px-(x1+t*dx), py-(y1+t*dy))
}

// sample 单子样本取色：u/v 为 viewBox 24 坐标。
func sample(u, v float64) (color.RGBA, bool) {
	if sdRoundBox(u, v, cx, cy, tileRadius) >= 0 {
		return color.RGBA{}, false // 圆角砖外：透明
	}
	// 声呐标记优先：中心点 > 环 > 刻度
	if math.Hypot(u-cx, v-cy) <= dotR {
		return colCenter, true
	}
	if d := math.Abs(math.Hypot(u-cx, v-cy) - ringR); d <= ringStroke/2 {
		return colRing, true
	}
	for _, t := range ticks {
		if sdSeg(u, v, t[0], t[1], t[2], t[3]) <= ringStroke/2 {
			return colRing, true
		}
	}
	return colTile, true
}

// paintSonar 画出边长 sz 的声呐图标（NRGBA 直通 alpha）。
func paintSonar(sz int) *image.NRGBA {
	img := image.NewNRGBA(image.Rect(0, 0, sz, sz))
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			var r, g, b, a float64
			for sy := 0; sy < subsamples; sy++ {
				for sx := 0; sx < subsamples; sx++ {
					u := (float64(x) + (float64(sx)+0.5)/subsamples) / float64(sz) * vb
					v := (float64(y) + (float64(sy)+0.5)/subsamples) / float64(sz) * vb
					if c, ok := sample(u, v); ok {
						r += float64(c.R)
						g += float64(c.G)
						b += float64(c.B)
						a += float64(c.A)
					}
				}
			}
			n := subsamples * subsamples
			i := img.PixOffset(x, y)
			img.Pix[i+0] = uint8(r/float64(n) + 0.5)
			img.Pix[i+1] = uint8(g/float64(n) + 0.5)
			img.Pix[i+2] = uint8(b/float64(n) + 0.5)
			img.Pix[i+3] = uint8(a/float64(n) + 0.5)
		}
	}
	return img
}

// encodePNG NRGBA 编码为 PNG 帧数据。
func encodePNG(img *image.NRGBA) []byte {
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

// frameKind 帧格式名（日志用）。
func frameKind(e ico.Entry) string {
	if e.PNG != nil {
		return "png"
	}
	return "bmp"
}

func main() {
	out := flag.String("o", "assets/icon.ico", "输出 .ico 路径")
	flag.Parse()

	entries := buildEntries()
	for _, e := range entries {
		n := len(e.PNG) + len(e.BMP)
		fmt.Fprintf(os.Stderr, "%4dpx  %6d 字节  %s\n", e.Size, n, frameKind(e))
	}
	data, err := ico.Encode(entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "打包 ico 失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "建输出目录失败: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "写 %s 失败: %v\n", *out, err)
		os.Exit(1)
	}
	// 落盘后立刻回读校验，保证资产自洽
	if _, err := ico.Parse(data); err != nil {
		fmt.Fprintf(os.Stderr, "回读校验失败: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("OK %s（%d 字节，%d 档尺寸）\n", *out, len(data), len(entries))
}
