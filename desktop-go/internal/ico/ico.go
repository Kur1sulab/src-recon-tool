// Package ico 组装 Windows .ico 容器（ICONDIR + ICONDIRENTRY + PNG 图数据）。
//
// 应用图标由 tools/genicon 以纯 Go 画出 PNG 后经此打包成 assets/icon.ico，
// 再由 rsrc 连同 app.manifest 编进 rsrc_windows_amd64.syso 嵌入 exe。
// 图数据统一 PNG 编码（Windows Vista+ 全尺寸支持；本工具 manifest 只声明 Win10/11）。
package ico

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Entry 单个图标帧：边长 Size（正方形，1–256），图数据二选一——
// PNG（仅建议 256 档）或 BMP（32bpp DIB，小尺寸全走它，LoadImage/GDI 只可靠解 BMP）。
type Entry struct {
	Size int
	PNG  []byte
	BMP  []byte
}

// imageData 返回该帧的图数据；两值都为空都非空时报错。
func (e Entry) imageData() ([]byte, error) {
	switch {
	case e.PNG != nil && e.BMP != nil:
		return nil, fmt.Errorf("ico: 条目尺寸 %d 的 PNG/BMP 数据同时设置", e.Size)
	case e.PNG != nil:
		if !bytes.HasPrefix(e.PNG, pngSignature) || len(e.PNG) < len(pngSignature)+8 {
			return nil, fmt.Errorf("ico: 尺寸 %d 不是有效的 PNG 图数据", e.Size)
		}
		return e.PNG, nil
	case e.BMP != nil:
		return e.BMP, nil
	default:
		return nil, fmt.Errorf("ico: 尺寸 %d 缺图数据（PNG/BMP 二选一）", e.Size)
	}
}

var pngSignature = []byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}

// dirSize = ICONDIR(6) + n * ICONDIRENTRY(16)。
func dirSize(n int) int { return 6 + n*16 }

// Encode 按条目顺序打包 .ico：目录在前，图数据依声明顺序紧随其后。
func Encode(entries []Entry) ([]byte, error) {
	if len(entries) == 0 {
		return nil, fmt.Errorf("ico: 至少要一个图标帧")
	}
	for i, e := range entries {
		if e.Size < 1 || e.Size > 256 {
			return nil, fmt.Errorf("ico: 条目 %d 尺寸 %d 越界（1–256）", i, e.Size)
		}
		if _, err := e.imageData(); err != nil {
			return nil, fmt.Errorf("ico: 条目 %d: %w", i, err)
		}
	}

	images := make([][]byte, len(entries))
	total := 0
	for i, e := range entries {
		images[i], _ = e.imageData() // 上面已整体校验过
		total += len(images[i])
	}

	buf := bytes.NewBuffer(make([]byte, 0, dirSize(len(entries))+total))
	_ = binary.Write(buf, binary.LittleEndian, uint16(0)) // reserved
	_ = binary.Write(buf, binary.LittleEndian, uint16(1)) // type: 图标
	_ = binary.Write(buf, binary.LittleEndian, uint16(len(entries)))

	offset := uint32(dirSize(len(entries)))
	type dirEntryFix struct {
		off int // 目录项里 imageOffset 字段的位置
		val uint32
	}
	fixups := make([]dirEntryFix, 0, len(entries))
	for i := range entries {
		buf.WriteByte(sideByte(entries[i].Size)) // 宽（256 记 0）
		buf.WriteByte(sideByte(entries[i].Size)) // 高
		buf.WriteByte(0)                         // 色数：无调色板记 0
		buf.WriteByte(0)                         // 保留
		_ = binary.Write(buf, binary.LittleEndian, uint16(1))  // planes
		_ = binary.Write(buf, binary.LittleEndian, uint16(32)) // bitCount
		_ = binary.Write(buf, binary.LittleEndian, uint32(len(images[i])))
		fixups = append(fixups, dirEntryFix{off: buf.Len(), val: offset})
		_ = binary.Write(buf, binary.LittleEndian, uint32(0)) // offset 先占位
		offset += uint32(len(images[i]))
	}
	for _, f := range fixups {
		binary.LittleEndian.PutUint32(buf.Bytes()[f.off:], f.val)
	}
	for _, img := range images {
		buf.Write(img)
	}
	return buf.Bytes(), nil
}

// sideByte 边长字节：256 按 ICO 规范记 0。
func sideByte(size int) byte {
	if size == 256 {
		return 0
	}
	return byte(size)
}

// Parse 读回 .ico（Encode 的逆操作），供测试与资产校验用。
func Parse(data []byte) ([]Entry, error) {
	if len(data) < 6 {
		return nil, fmt.Errorf("ico: 数据过短（%d 字节，不足 ICONDIR）", len(data))
	}
	if got := binary.LittleEndian.Uint16(data[2:4]); got != 1 {
		return nil, fmt.Errorf("ico: 类型 %d 不是图标文件", got)
	}
	n := int(binary.LittleEndian.Uint16(data[4:6]))
	if len(data) < dirSize(n) {
		return nil, fmt.Errorf("ico: 目录声称 %d 条目，数据不够", n)
	}
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		d := data[6+i*16 : 6+(i+1)*16]
		size := int(d[0])
		if size == 0 {
			size = 256
		}
		length := int(binary.LittleEndian.Uint32(d[8:12]))
		offset := int(binary.LittleEndian.Uint32(d[12:16]))
		if offset+length > len(data) || offset+length < offset {
			return nil, fmt.Errorf("ico: 条目 %d 图数据越界（offset=%d len=%d 总长=%d）", i, offset, length, len(data))
		}
		png := data[offset : offset+length]
		if bytes.HasPrefix(png, pngSignature) {
			entries = append(entries, Entry{Size: size, PNG: append([]byte(nil), png...)})
			continue
		}
		entries = append(entries, Entry{Size: size, BMP: append([]byte(nil), png...)})
	}
	return entries, nil
}
