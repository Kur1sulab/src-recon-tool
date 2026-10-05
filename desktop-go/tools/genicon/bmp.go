package main

import (
	"encoding/binary"
	"fmt"
	"image"

	"recon-desktop/internal/ico"
)

// encodeBMPFrame 把 NRGBA 图编码成 ICO 里的 32bpp BMP(DIB) 帧：
// BITMAPINFOHEADER（biHeight 双高）+ 自底向上 BGRA 像素 + 全 0 AND 掩码
//（透明度全交 alpha 通道——GDI/LoadImage 的标准解读）。
func encodeBMPFrame(img *image.NRGBA) ([]byte, error) {
	b := img.Bounds()
	sz := b.Dx()
	if b.Dy() != sz {
		return nil, fmt.Errorf("bmp: 图必须正方形（%dx%d）", b.Dx(), b.Dy())
	}
	maskRow := ((sz + 31) / 32) * 4
	dib := make([]byte, 40+sz*sz*4+maskRow*sz)

	binary.LittleEndian.PutUint32(dib[0:4], 40)                       // biSize
	binary.LittleEndian.PutUint32(dib[4:8], uint32(sz))               // biWidth
	binary.LittleEndian.PutUint32(dib[8:12], uint32(2*sz))            // biHeight（像素+掩码，双高约定）
	binary.LittleEndian.PutUint16(dib[12:14], 1)                      // biPlanes
	binary.LittleEndian.PutUint16(dib[14:16], 32)                     // biBitCount
	binary.LittleEndian.PutUint32(dib[16:20], 0)                      // biCompression = BI_RGB
	// biSizeImage 等其余字段保持 0（BI_RGB 下合法）

	px := dib[40 : 40+sz*sz*4]
	for y := 0; y < sz; y++ { // 自底向上
		src := img.Pix[img.PixOffset(0, sz-1-y):]
		row := px[y*sz*4 : (y+1)*sz*4]
		for x := 0; x < sz; x++ {
			row[x*4+0] = src[x*4+2] // B
			row[x*4+1] = src[x*4+1] // G
			row[x*4+2] = src[x*4+0] // R
			row[x*4+3] = src[x*4+3] // A
		}
	}
	// AND 掩码区已由 make 置 0：32bpp 下掩码全 0 = 透明度由 alpha 通道决定
	return dib, nil
}

// buildEntries 全尺寸档生成图标帧：≤128 走 BMP（LoadImage/GDI 只可靠解 BMP 帧），
// 256 走 PNG（资源管理器大视图的壳层编解码器官方支持档）。
func buildEntries() []ico.Entry {
	entries := make([]ico.Entry, 0, len(iconSizes))
	for _, sz := range iconSizes {
		img := paintSonar(sz)
		if sz <= 128 {
			dib, err := encodeBMPFrame(img)
			if err != nil {
				panic(err) // 尺寸/正方形在 iconSizes 里已约束，到此必不触发
			}
			entries = append(entries, ico.Entry{Size: sz, BMP: dib})
			continue
		}
		entries = append(entries, ico.Entry{Size: sz, PNG: encodePNG(img)})
	}
	return entries
}
