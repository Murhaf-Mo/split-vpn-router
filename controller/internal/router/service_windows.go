package router

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/vpn/controller/internal/config"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const ServiceName = "VPNRouter"

func rootDir() string {
	path, err := windows.KnownFolderPath(windows.FOLDERID_ProgramData, 0)
	if err != nil {
		path = os.Getenv("ProgramData")
	}
	return filepath.Join(path, "VPNRouter")
}
func StatusDirectory() string { return filepath.Join(rootDir(), "public") }
func binaryDirectory() string { return filepath.Join(rootDir(), "bin") }

func installBinary(source, target string) error {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	random := make([]byte, 8)
	if _, err = rand.Read(random); err != nil {
		return err
	}
	temporary := target + "." + hex.EncodeToString(random) + ".new"
	sd, err := windows.SecurityDescriptorFromString(`O:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FRFX;;;BU)`)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	native, _ := windows.UTF16PtrFromString(temporary)
	handle, err := windows.CreateFile(native, windows.GENERIC_WRITE, windows.FILE_SHARE_READ, &attributes, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return err
	}
	output := os.NewFile(uintptr(handle), temporary)
	_, copyErr := io.Copy(output, input)
	closeErr := output.Close()
	defer os.Remove(temporary)
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
		if err = os.Rename(temporary, target); err == nil {
			return nil
		}
	}
	return err
}

func fileHash(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

type Snapshot struct {
	Active  bool   `json:"active"`
	Ready   bool   `json:"ready"`
	Error   string `json:"error"`
	Updated int64  `json:"updated"`
}

func secure(path, sddl string) error {
	if info, err := os.Lstat(path); err != nil {
		return err
	} else if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing a reparse point at %s", path)
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, owner, nil, dacl, nil)
}

// Create service directories with their protected ACL atomically. An existing
// user-owned directory must never become a privileged service work directory.
func protectedDirectory(path string, public bool) error {
	sddl := `O:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)`
	if public {
		sddl += `(A;OICI;FRFX;;;BU)`
	} else {
		sddl += `(A;;FRFX;;;BU)`
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	native, _ := windows.UTF16PtrFromString(path)
	attributes := windows.SecurityAttributes{Length: uint32(unsafe.Sizeof(windows.SecurityAttributes{})), SecurityDescriptor: sd}
	err = windows.CreateDirectory(native, &attributes)
	if err != nil && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
		return err
	}
	if info, err := os.Lstat(path); err != nil {
		return err
	} else if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("service directory must be a regular directory: %s", path)
	}
	existing, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	owner, _, err := existing.Owner()
	if err != nil {
		return err
	}
	admins, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	system, _ := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if !owner.Equals(admins) && !owner.Equals(system) {
		return fmt.Errorf("service directory has an untrusted owner; an administrator must remove %s before installation", path)
	}
	return secure(path, sddl)
}

func writeStatus(active bool, message string) {
	writeSnapshot(active, active, message)
}

func writeReadyStatus() { writeSnapshot(false, true, "") }

func writeSnapshot(active, ready bool, message string) {
	body, _ := json.Marshal(Snapshot{Active: active, Ready: ready, Error: message, Updated: time.Now().Unix()})
	path := filepath.Join(StatusDirectory(), "status.json")
	tmp := path + ".tmp"
	if os.WriteFile(tmp, body, 0600) != nil {
		return
	}
	if secure(tmp, `D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)`) == nil {
		for attempt := 0; attempt < 5; attempt++ {
			if os.Rename(tmp, path) == nil {
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

func ReadStatus() Snapshot {
	var status Snapshot
	b, err := os.ReadFile(filepath.Join(StatusDirectory(), "status.json"))
	if err == nil {
		_ = json.Unmarshal(b, &status)
	}
	if !Running() {
		status.Active = false
	}
	return status
}

func Admin() bool {
	sid, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	yes, _ := windows.Token(0).IsMember(sid)
	return yes
}

// Prepare is called only by the elevated helper. Normal users can subsequently
// start/stop this service, but cannot replace its executable or service configuration.
func Prepare(data string) error {
	if !Admin() {
		return fmt.Errorf("router service installation requires administrator rights")
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	sourceDirectory := filepath.Dir(exe)
	data, err = filepath.Abs(data)
	if err != nil {
		return err
	}
	root := rootDir()
	if info, err := os.Lstat(root); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("service directory must not be a link")
	}
	if err := protectedDirectory(root, false); err != nil {
		return err
	}
	if err := protectedDirectory(StatusDirectory(), true); err != nil {
		return err
	}
	if err := protectedDirectory(binaryDirectory(), true); err != nil {
		return err
	}
	exe = filepath.Join(binaryDirectory(), "vpn.exe")
	writeStatus(false, "")
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	args := []string{"router-service", "--data-dir", data}
	if err == nil {
		defer s.Close()
		cfg, err := s.Config()
		if err != nil {
			return err
		}
		expected := syscall.EscapeArg(exe)
		for _, arg := range args {
			expected += " " + syscall.EscapeArg(arg)
		}
		if !strings.EqualFold(cfg.BinaryPathName, expected) {
			return fmt.Errorf("VPNRouter belongs to a different installation/user; uninstall that router service first")
		}
		state, err := s.Query()
		if err != nil {
			return err
		}
		if state.State != svc.Stopped {
			if err := Control(false); err != nil {
				return err
			}
		}
	} else {
		if !errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return err
		}
		s, err = m.CreateService(ServiceName, exe, mgr.Config{DisplayName: "VPN Router", StartType: mgr.StartManual, Description: "Windows TUN router for the Docker VPN runtime"}, args...)
		if err != nil {
			return err
		}
		defer s.Close()
	}
	if err := recoverForwarding(); err != nil {
		return err
	}
	for _, name := range []string{"vpn.exe", "sing-box.exe", "libcronet.dll", "sing-box-LICENSE.txt"} {
		if err := installBinary(filepath.Join(sourceDirectory, name), filepath.Join(binaryDirectory(), name)); err != nil {
			return fmt.Errorf("installing protected routing executable %s: %w", name, err)
		}
	}
	token := windows.GetCurrentProcessToken()
	user, err := token.GetTokenUser()
	if err != nil {
		return err
	}
	sddl := `D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;CCLCRPWPLO;;;` + user.User.Sid.String() + `)`
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(s.Handle, windows.SE_SERVICE, windows.DACL_SECURITY_INFORMATION, nil, nil, acl, nil); err != nil {
		return err
	}
	// No service recovery action reconnects or logs into the VPN.
	return nil
}

func connectManager() (*mgr.Mgr, error) {
	h, e := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if e != nil {
		return nil, e
	}
	return &mgr.Mgr{Handle: h}, nil
}
func openService(m *mgr.Mgr, access uint32) (*mgr.Service, error) {
	name, _ := windows.UTF16PtrFromString(ServiceName)
	h, e := windows.OpenService(m.Handle, name, access)
	if e != nil {
		return nil, e
	}
	return &mgr.Service{Name: ServiceName, Handle: h}, nil
}

func Installed() bool {
	m, e := connectManager()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	s, e := openService(m, windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return false
	}
	s.Close()
	return true
}

func PreparedFor(install, data string) error {
	m, err := connectManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return err
	}
	defer s.Close()
	cfg, err := s.Config()
	if err != nil {
		return err
	}
	expected := syscall.EscapeArg(filepath.Join(binaryDirectory(), "vpn.exe")) + " router-service --data-dir " + syscall.EscapeArg(data)
	if !strings.EqualFold(cfg.BinaryPathName, expected) {
		return fmt.Errorf("the Windows router service belongs to a different installation; remove it with vpn router-uninstall as administrator first")
	}
	for _, name := range []string{"vpn.exe", "sing-box.exe", "libcronet.dll"} {
		source, err := fileHash(filepath.Join(install, name))
		if err != nil {
			return err
		}
		installed, err := fileHash(filepath.Join(binaryDirectory(), name))
		if err != nil || source != installed {
			return fmt.Errorf("protected routing binaries need to be updated")
		}
	}
	return nil
}
func Running() bool {
	m, e := connectManager()
	if e != nil {
		return false
	}
	defer m.Disconnect()
	s, e := openService(m, windows.SERVICE_QUERY_STATUS)
	if e != nil {
		return false
	}
	defer s.Close()
	status, e := s.Query()
	return e == nil && status.State == svc.Running
}

func Control(start bool) error {
	return control(start, true)
}

func StartIdle() error { return control(true, false) }

func control(start, waitAdapter bool) error {
	m, err := connectManager()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := openService(m, windows.SERVICE_QUERY_STATUS|windows.SERVICE_START|windows.SERVICE_STOP)
	if err != nil {
		return err
	}
	defer s.Close()
	status, err := s.Query()
	if err != nil {
		return err
	}
	if start && status.State != svc.Running {
		if err = s.Start(); err != nil && !errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
			return err
		}
	}
	if !start && status.State != svc.Stopped {
		if _, err = s.Control(svc.Stop); err != nil {
			return err
		}
	}
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); {
		status, err = s.Query()
		if err != nil {
			return err
		}
		if !start && status.State == svc.Stopped {
			return nil
		}
		if start && status.State == svc.Running {
			if !waitAdapter {
				return nil
			}
			snap := ReadStatus()
			if snap.Active {
				return nil
			}
			if snap.Error != "" {
				return fmt.Errorf("Windows router: %s", snap.Error)
			}
		}
		if start && status.State == svc.Stopped {
			return fmt.Errorf("Windows router stopped during startup")
		}
		time.Sleep(300 * time.Millisecond)
	}
	return fmt.Errorf("Windows router service did not finish changing state")
}

func Remove() error {
	if !Admin() {
		return fmt.Errorf("run vpn router-uninstall from an administrator terminal")
	}
	if !Installed() {
		return nil
	}
	if err := Control(false); err != nil {
		return err
	}
	if err := recoverForwarding(); err != nil {
		return err
	}
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()
	s, err := m.OpenService(ServiceName)
	if err != nil {
		return err
	}
	defer s.Close()
	return s.Delete()
}

// Elevate waits for the concrete service installation helper, never for VPN authentication.
func Elevate(data string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	// The tray executable delegates to its CLI sibling.
	exe = filepath.Join(filepath.Dir(exe), "vpn.exe")
	type shellInfo struct {
		Size, Mask                    uint32
		Window                        windows.Handle
		Verb, File, Params, Directory *uint16
		Show                          int32
		Instance                      windows.Handle
		IDList                        uintptr
		Class                         *uint16
		Key                           windows.Handle
		HotKey                        uint32
		Icon                          windows.Handle
		Process                       windows.Handle
	}
	verb, _ := windows.UTF16PtrFromString("runas")
	file, _ := windows.UTF16PtrFromString(exe)
	params, _ := windows.UTF16PtrFromString("router-prepare --data-dir " + syscall.EscapeArg(data))
	info := shellInfo{Mask: 0x40, Verb: verb, File: file, Params: params, Show: 0}
	info.Size = uint32(unsafe.Sizeof(info))
	result, _, callErr := windows.NewLazySystemDLL("shell32.dll").NewProc("ShellExecuteExW").Call(uintptr(unsafe.Pointer(&info)))
	if result == 0 {
		return fmt.Errorf("service installation was not approved: %w", callErr)
	}
	defer windows.CloseHandle(info.Process)
	wait, err := windows.WaitForSingleObject(info.Process, 120000)
	if err != nil {
		return err
	}
	if wait != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("service installation timed out")
	}
	var code uint32
	if err := windows.GetExitCodeProcess(info.Process, &code); err != nil {
		return err
	}
	if code != 0 {
		return fmt.Errorf("service installer failed; run vpn router-prepare --data-dir %q in an administrator terminal for details", data)
	}
	return nil
}

type handler struct{ data, install string }

func Serve(data string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return svc.Run(ServiceName, &handler{data, filepath.Dir(exe)})
}

var errVPNNotReady = errors.New("VPN network is not ready")

func readPolicy(data string, lastNetwork *string) (Policy, [32]byte, error) {
	cfg, err := config.Load(filepath.Join(data, "config.toml"))
	if err != nil {
		return Policy{}, [32]byte{}, err
	}
	read := func(name string) string { b, _ := os.ReadFile(filepath.Join(data, name)); return string(b) }
	vpn, direct := read("vpn.list"), read("direct.list")
	for _, list := range []string{vpn, direct} {
		for _, entry := range ParseList(list) {
			if _, err := Matcher(entry); err != nil {
				return Policy{}, [32]byte{}, err
			}
		}
	}
	key := strings.TrimSpace(read("runtime/relay.key"))
	networkBytes := read("runtime/network.json")
	if networkBytes == "" {
		networkBytes = *lastNetwork
	}
	var network struct {
		DNS     []string `json:"dns"`
		Gateway string   `json:"gateway"`
	}
	if err := json.Unmarshal([]byte(networkBytes), &network); err != nil {
		return Policy{}, [32]byte{}, errVPNNotReady
	}
	*lastNetwork = networkBytes
	dns := cfg.DNS
	if dns == "" && len(network.DNS) > 0 {
		dns = network.DNS[0]
	}
	hosts, _ := os.ReadFile(filepath.Join(os.Getenv("SystemRoot"), "System32", "drivers", "etc", "hosts"))
	policy := Policy{Mode: cfg.Mode, Key: key, RelayPort: cfg.RelayPort, DirectDNS: cfg.DirectDNS, CorpDNS: dns, Gateway: network.Gateway, VPNHost: cfg.VPNHost, RouterProcessPath: filepath.Join(binaryDirectory(), "sing-box.exe"),
		VPN: ParseList(vpn), Direct: ParseList(direct), Hosts: string(hosts)}
	policyBytes, _ := json.Marshal(policy)
	hash := sha256.Sum256(policyBytes)
	if len(key) != 64 {
		return Policy{}, hash, fmt.Errorf("relay key is missing")
	}
	return policy, hash, nil
}

type child struct {
	cmd  *exec.Cmd
	done chan error
	log  *os.File
	job  windows.Handle
}

func launch(exe, conf string) (*child, error) {
	logfile, err := os.OpenFile(filepath.Join(rootDir(), "router.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	check := exec.CommandContext(ctx, exe, "check", "-c", conf)
	check.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := check.CombinedOutput(); err != nil {
		logfile.Close()
		return nil, fmt.Errorf("invalid router configuration: %s", out)
	}
	cmd := exec.Command(exe, "run", "-c", conf)
	cmd.Dir = rootDir()
	cmd.Stdout = logfile
	cmd.Stderr = logfile
	// A hidden dedicated console allows a graceful Ctrl-C on service stop/reload.
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NEW_CONSOLE}
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		logfile.Close()
		return nil, err
	}
	info := windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION{}
	info.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	if _, err := windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		windows.CloseHandle(job)
		logfile.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		windows.CloseHandle(job)
		logfile.Close()
		return nil, err
	}
	process, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err == nil {
		err = windows.AssignProcessToJobObject(job, process)
		windows.CloseHandle(process)
	}
	if err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		windows.CloseHandle(job)
		logfile.Close()
		return nil, err
	}
	c := &child{cmd: cmd, done: make(chan error, 1), log: logfile, job: job}
	go func() { c.done <- cmd.Wait() }()
	return c, nil
}

// Run only in a short-lived helper. Attaching the service itself to a console
// can deliver its child's asynchronous Ctrl-C to the service during detach.
func SignalChild(pid uint32) error {
	if !Admin() {
		return fmt.Errorf("routing process signaling requires administrator rights")
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, pid)
	if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		return nil
	}
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var path [32768]uint16
	size := uint32(len(path))
	if err := windows.QueryFullProcessImageName(h, 0, &path[0], &size); err != nil {
		return err
	}
	if !strings.EqualFold(windows.UTF16ToString(path[:size]), filepath.Join(binaryDirectory(), "sing-box.exe")) {
		return fmt.Errorf("refusing to signal an unrelated process")
	}
	kernel := windows.NewLazySystemDLL("kernel32.dll")
	if ok, _, callErr := kernel.NewProc("AttachConsole").Call(uintptr(pid)); ok == 0 {
		return callErr
	}
	defer kernel.NewProc("FreeConsole").Call()
	kernel.NewProc("SetConsoleCtrlHandler").Call(0, 1)
	if ok, _, callErr := kernel.NewProc("GenerateConsoleCtrlEvent").Call(0, 0); ok == 0 {
		return callErr
	}
	_, err = windows.WaitForSingleObject(h, 2000)
	return err
}

func (c *child) stop() {
	select {
	case <-c.done:
		windows.CloseHandle(c.job)
		c.log.Close()
		return
	default:
	}
	if exe, err := os.Executable(); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		helper := exec.CommandContext(ctx, exe, "router-signal", strconv.Itoa(c.cmd.Process.Pid))
		helper.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW}
		if err := helper.Run(); err != nil {
			fmt.Fprintln(c.log, "graceful stop helper:", err)
		}
		cancel()
	}
	select {
	case <-c.done:
	case <-time.After(8 * time.Second):
		_ = c.cmd.Process.Kill()
		<-c.done
	}
	windows.CloseHandle(c.job)
	c.log.Close()
}

func (h *handler) Execute(_ []string, requests <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	status <- svc.Status{State: svc.StartPending}
	writeStatus(false, "")
	binary := filepath.Join(h.install, "sing-box.exe")
	conf := filepath.Join(rootDir(), "router.json")
	var current *child
	var forwarding *forwardingLease
	finalError := ""
	lastNetwork := ""
	defer func() {
		if current != nil {
			current.stop()
		}
		if forwarding != nil {
			if err := forwarding.close(); err != nil {
				finalError += " " + err.Error()
			}
		}
		writeStatus(false, finalError)
		windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
	}()
	cfg, err := config.Load(filepath.Join(h.data, "config.toml"))
	if err != nil {
		finalError = err.Error()
		return false, 1
	}
	if err := CheckForwarding(cfg.ManageForwarding); err != nil {
		writeStatus(false, err.Error())
	} else {
		writeReadyStatus()
	}
	var previous [32]byte
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	status <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for {
		select {
		case req := <-requests:
			if req.Cmd == svc.Stop || req.Cmd == svc.Shutdown {
				status <- svc.Status{State: svc.StopPending}
				return false, 0
			}
			if req.Cmd == svc.Interrogate {
				status <- req.CurrentStatus
			}
		case <-tick.C:
			if forwarding != nil {
				if err := forwarding.ensure(); err != nil {
					finalError = err.Error()
					status <- svc.Status{State: svc.StopPending}
					return false, 1
				}
			}
			cfg, err = config.Load(filepath.Join(h.data, "config.toml"))
			if err != nil {
				writeStatus(current != nil, err.Error())
				continue
			}
			if forwarding == nil {
				if err := CheckForwarding(cfg.ManageForwarding); err != nil {
					writeStatus(false, err.Error())
					continue
				}
			}
			if current != nil {
				select {
				case err := <-current.done:
					windows.CloseHandle(current.job)
					current.log.Close()
					current = nil
					finalError = fmt.Sprintf("routing process exited: %v; use vpn up to restart", err)
					writeStatus(false, finalError)
					// Do not spin in a restart loop or disturb the network after a fatal error.
					status <- svc.Status{State: svc.StopPending}
					return false, 1
				default:
				}
			}
			policy, hash, err := readPolicy(h.data, &lastNetwork)
			if err != nil {
				if current == nil && errors.Is(err, errVPNNotReady) {
					writeReadyStatus()
					continue
				}
				writeStatus(current != nil, err.Error())
				continue
			}
			if forwarding == nil {
				forwarding, err = beginForwarding(cfg.ManageForwarding)
				if err != nil {
					writeStatus(false, err.Error())
					continue
				}
			}
			if current != nil && hash == previous {
				writeStatus(true, "")
				continue
			}
			body, err := Generate(policy)
			if err != nil {
				writeStatus(current != nil, err.Error())
				continue
			}
			tmp := conf + ".tmp"
			if err = os.WriteFile(tmp, body, 0600); err != nil {
				writeStatus(current != nil, err.Error())
				continue
			}
			// Validate before stopping the working data plane.
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			check := exec.CommandContext(ctx, binary, "check", "-c", tmp)
			check.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
			out, err := check.CombinedOutput()
			cancel()
			if err != nil {
				writeStatus(current != nil, fmt.Sprintf("invalid routing configuration: %s", out))
				continue
			}
			if current != nil {
				writeStatus(false, "Applying routing changes")
				current.stop()
				current = nil
			}
			if err = os.Rename(tmp, conf); err != nil {
				writeStatus(false, err.Error())
				continue
			}
			current, err = launch(binary, conf)
			if err != nil {
				writeStatus(false, err.Error())
				continue
			}
			previous = hash
			ready := false
			for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(100 * time.Millisecond) {
				interfaces, _ := net.Interfaces()
				for _, adapter := range interfaces {
					if adapter.Name == "VPN Router" && adapter.Flags&net.FlagUp != 0 {
						ready = true
						break
					}
				}
				if ready {
					break
				}
			}
			if !ready {
				finalError = "virtual adapter did not become ready; inspect the administrator-only router.log"
				return false, 1
			}
			writeStatus(true, "")
			windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsFlushResolverCache").Call()
		}
	}
}
