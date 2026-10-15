// vpn — Windows-side controller for the Docker VPN runtime and native Windows TUN router.
//
// One binary, two modes:
//   - CLI:  `vpn up`, `vpn status`, etc. (the same verb surface vpn.ps1 had)
//   - Tray: `vpn tray` (or no args) runs a system-tray UI.
package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/vpn/controller/internal/backend"
	"github.com/vpn/controller/internal/cli"
	"github.com/vpn/controller/internal/release"
	"github.com/vpn/controller/internal/router"
	"github.com/vpn/controller/internal/tray"
	"github.com/vpn/controller/internal/winproxy"
)

func main() {
	args := os.Args[1:]
	verb := ""
	if len(args) > 0 {
		verb = args[0]
		args = args[1:]
	}

	// help / version / configure run BEFORE LoadEnv so they work even when
	// no config.toml exists yet (fresh install path).
	switch verb {
	case "down":
		exitOnErr(cli.EmergencyDown())
		return
	case "router-service", "router-prepare":
		if len(args) != 2 || args[0] != "--data-dir" {
			exitOnErr(fmt.Errorf("--data-dir is required"))
			return
		}
		if verb == "router-service" {
			exitOnErr(router.Serve(args[1]))
		} else {
			exitOnErr(router.Prepare(args[1]))
		}
		return
	case "router-uninstall":
		exitOnErr(router.Remove())
		return
	case "router-watchdog":
		if len(args) != 1 {
			exitOnErr(fmt.Errorf("forwarding recovery lease is required"))
			return
		}
		exitOnErr(router.WatchForwarding(args[0]))
		return
	case "router-signal":
		if len(args) != 1 {
			exitOnErr(fmt.Errorf("routing child PID is required"))
			return
		}
		pid, err := strconv.ParseUint(args[0], 10, 32)
		if err != nil {
			exitOnErr(err)
			return
		}
		exitOnErr(router.SignalChild(uint32(pid)))
		return
	case "repair-proxy":
		exitOnErr(winproxy.CleanupLegacy())
		return
	case "help", "--help", "-h":
		cli.Usage()
		return
	case "version", "--version":
		fmt.Println("vpn", release.LocalVersion())
		return
	case "configure":
		exitOnErr(cli.Configure(args))
		return
	case "upgrade":
		// Upgrade doesn't need a loaded env — it deals only with the
		// release pipeline and msiexec.
		exitOnErr(cli.Upgrade(args))
		return
	}

	env, err := cli.LoadEnv()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}

	switch verb {
	case "", "tray":
		tray.Run(env)
	case "up":
		exitOnErr(cli.Up(env))
	case "down":
		exitOnErr(cli.Down(env))
	case "restart":
		exitOnErr(cli.Restart(env))
	case "build-image":
		exitOnErr(backend.Build(env.InstallDir, env.Cfg))
	case "status":
		exitOnErr(cli.Status(env))
	case "mode":
		exitOnErr(cli.Mode(env, args))
	case "add":
		exitOnErr(cli.Add(env, args))
	case "remove", "rm":
		exitOnErr(cli.Remove(env, args))
	case "list", "ls":
		exitOnErr(cli.List(env))
	case "logs":
		exitOnErr(cli.Logs(env, args))
	case "reload":
		exitOnErr(cli.Reload(env))
	case "sync-hosts":
		exitOnErr(cli.SyncHosts(env))
	case "autostart":
		exitOnErr(cli.Autostart(env, args))
	case "dashboard", "open":
		exitOnErr(cli.OpenDashboard(env, ""))
	default:
		fmt.Fprintln(os.Stderr, "unknown verb:", verb)
		cli.Usage()
		os.Exit(2)
	}
}

func exitOnErr(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}
