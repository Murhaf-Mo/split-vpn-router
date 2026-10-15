// Package backend controls only locally managed Docker containers. It never calls WSL.
package backend

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/vpn/controller/internal/config"
	"github.com/vpn/controller/internal/router"
)

const label = "io.github.murhaf-mo.vpn-router"

func Command(ctx context.Context, args ...string) *exec.Cmd {
	path, err := exec.LookPath("docker.exe")
	if err != nil {
		path = filepath.Join(os.Getenv("ProgramFiles"), "Docker", "Docker", "resources", "bin", "docker.exe")
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

func run(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	out, err := Command(ctx, args...).CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("docker: %w: %s", err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

func Name(data string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(data)))
	return "vpn-router-" + hex.EncodeToString(sum[:6])
}

func EnsureSecrets(data string) error {
	rt := filepath.Join(data, "runtime")
	if err := os.MkdirAll(rt, 0700); err != nil {
		return err
	}
	for _, name := range []string{"api.token", "relay.key"} {
		path := filepath.Join(rt, name)
		if b, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(b))) == 64 {
			continue
		}
		b := make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(hex.EncodeToString(b)), 0600); err != nil {
			return err
		}
	}
	return nil
}

func Token(data string) string {
	b, _ := os.ReadFile(filepath.Join(data, "runtime", "api.token"))
	return strings.TrimSpace(string(b))
}

func Check() error {
	// Port publishing must refer to this Windows computer, never a remote Docker context.
	endpoint, err := run("context", "inspect", "--format", "{{.Endpoints.docker.Host}}")
	if err != nil {
		return err
	}
	if !strings.HasPrefix(endpoint, "npipe://") {
		return fmt.Errorf("use a local Docker Desktop context (current endpoint: %s)", endpoint)
	}
	if os.Getenv("DOCKER_HOST") != "" {
		return fmt.Errorf("unset DOCKER_HOST; remote Docker engines are unsupported")
	}
	kind, err := run("info", "--format", "{{.OSType}}")
	if err != nil {
		return fmt.Errorf("start Docker Desktop with Linux containers: %w", err)
	}
	if kind != "linux" {
		return fmt.Errorf("switch Docker Desktop to Linux containers")
	}
	return nil
}

func Build(install string, c *config.Config) error {
	if err := Check(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	signature, err := sourceSignature(install)
	if err != nil {
		return err
	}
	cmd := Command(ctx, "build", "--platform", "linux/amd64", "--label", label+".source="+signature, "-t", c.Image, install)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func Start(install, data, version string, c *config.Config) error {
	if err := Check(); err != nil {
		return err
	}
	if err := EnsureSecrets(data); err != nil {
		return err
	}
	signature, err := sourceSignature(install)
	if err != nil {
		return err
	}
	builtSignature, inspectErr := run("image", "inspect", "--format", `{{index .Config.Labels "`+label+`.source"}}`, c.Image)
	if inspectErr != nil || builtSignature != signature {
		if err := Build(install, c); err != nil {
			return err
		}
	}
	if err := Stop(data); err != nil {
		return err
	}
	// Never activate Windows routing from metadata left by a previous container.
	if err := os.Remove(filepath.Join(data, "runtime", "network.json")); err != nil && !os.IsNotExist(err) {
		return err
	}
	var mount strings.Builder
	writer := csv.NewWriter(&mount)
	_ = writer.Write([]string{"type=bind", "source=" + data, "target=/data"})
	writer.Flush()
	var healthMount strings.Builder
	healthWriter := csv.NewWriter(&healthMount)
	_ = healthWriter.Write([]string{"type=bind", "source=" + router.StatusDirectory(), "target=/router-status", "readonly"})
	healthWriter.Flush()
	_, err = run("run", "-d", "--name", Name(data), "--label", label+"="+Name(data),
		"--platform", "linux/amd64", "--restart=no", "--init", "--read-only", "--tmpfs", "/tmp",
		"--cap-drop=ALL", "--cap-add=NET_ADMIN", "--device=/dev/net/tun", "--security-opt=no-new-privileges:true",
		"--mount", strings.TrimSpace(mount.String()),
		"--mount", strings.TrimSpace(healthMount.String()),
		"-e", "VPN_VERSION="+version,
		"-p", "127.0.0.1:"+strconv.Itoa(c.APIport)+":"+strconv.Itoa(c.APIport)+"/tcp",
		"-p", "127.0.0.1:"+strconv.Itoa(c.RelayPort)+":"+strconv.Itoa(c.RelayPort)+"/tcp",
		"-p", "127.0.0.1:"+strconv.Itoa(c.RelayPort)+":"+strconv.Itoa(c.RelayPort)+"/udp", c.Image)
	return err
}

func sourceSignature(install string) (string, error) {
	hash := sha256.New()
	for _, name := range []string{"Dockerfile", ".dockerignore", "vpnctl.py", "vpnc-script.py", "static/index.html", "static/app.js", "static/style.css"} {
		b, err := os.ReadFile(filepath.Join(install, name))
		if err != nil {
			return "", err
		}
		hash.Write([]byte(name))
		hash.Write([]byte{0})
		hash.Write(b)
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// Check the running container's immutable image, not the possibly updated tag.
func Current(install, data string) bool {
	signature, err := sourceSignature(install)
	if err != nil {
		return false
	}
	image, err := run("inspect", "--format", "{{.Image}}", Name(data))
	if err != nil {
		return false
	}
	built, err := run("image", "inspect", "--format", `{{index .Config.Labels "`+label+`.source"}}`, image)
	return err == nil && built == signature
}

func Stop(data string) error {
	name := Name(data)
	// A missing container is fine. An inspection failure otherwise must not delete anything.
	names, err := run("ps", "-a", "--filter", "name=^/"+name+"$", "--format", "{{.Names}}")
	if err != nil {
		return err
	}
	if names == "" {
		return nil
	}
	owner, err := run("inspect", "--format", `{{index .Config.Labels "`+label+`"}}`, name)
	if err != nil {
		return err
	}
	if owner != name {
		return fmt.Errorf("refusing to remove an unmanaged container named %s", name)
	}
	_, err = run("rm", "-f", name)
	return err
}
