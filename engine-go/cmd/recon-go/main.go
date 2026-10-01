// recon-go 标准布局入口（engine-go/cmd/recon-go）。
// 全部 CLI 逻辑在 internal/cli，此处仅做薄壳——go build ./cmd/recon-go。
package main

import (
	"os"

	"github.com/Kur1sulab/src-recon-tool/engine-go/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:]))
}
