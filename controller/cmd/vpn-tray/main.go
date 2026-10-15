// vpn-tray — windowsgui twin of vpn.exe that only runs the tray UI.
// No console window appears on launch.
package main

import (
	"os"

	"github.com/vpn/controller/internal/cli"
	"github.com/vpn/controller/internal/platform"
	"github.com/vpn/controller/internal/tray"
)

func main() {
	env, err := cli.LoadEnv()
	if err != nil {
		data, _ := platform.DataDir()
		tray.ReportError(data, "startup (run vpn configure if credentials are missing)", err)
		os.Exit(1)
	}
	tray.Run(env)
}
