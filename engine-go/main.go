// recon-go 根目录兼容入口：逻辑已迁至 internal/cli + cmd/recon-go/main.go，
// 此薄壳保留是为了旧验收命令 `go build -o recon-go.exe .`（engine-go 根）继续可用。
// 两个入口产出的二进制行为完全一致。
package main

import (
	"os"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
