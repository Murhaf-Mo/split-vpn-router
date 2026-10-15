package router

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type forwardingEntry struct {
	LUID   uint64 `json:"luid"`
	Family uint16 `json:"family"`
}
type forwardingState struct {
	ID      string            `json:"id"`
	PID     uint32            `json:"pid"`
	Created int64             `json:"created"`
	Entries []forwardingEntry `json:"entries"`
}
type forwardingLease struct {
	lock   windows.Handle
	state  forwardingState
	manage bool
}

func forwardingPath() string { return filepath.Join(rootDir(), "forwarding-state.json") }

// Lock ownership belongs to the file handle, rather than a Go OS thread. An
// unclean service exit releases it before the independent watchdog restores state.
func forwardingLock() (windows.Handle, error) {
	p, _ := windows.UTF16PtrFromString(filepath.Join(rootDir(), "forwarding.lock"))
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		h, err := windows.CreateFile(p, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Now().After(deadline) {
			return h, err
		}
	}
}

func defaultForwardingInterfaces() ([]windows.MibIpInterfaceRow, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(windows.AF_UNSPEC, &table); err != nil {
		return nil, err
	}
	defer windows.FreeMibTable(unsafe.Pointer(table))
	type choice struct {
		row    windows.MibIpInterfaceRow
		metric uint64
	}
	best := map[uint16]choice{}
	for _, route := range table.Rows() {
		if route.DestinationPrefix.PrefixLength != 0 || route.Loopback != 0 {
			continue
		}
		adapter, err := net.InterfaceByIndex(int(route.InterfaceIndex))
		if err != nil || adapter.Name == "VPN Router" || adapter.Flags&net.FlagUp == 0 {
			continue
		}
		row := windows.MibIpInterfaceRow{Family: route.DestinationPrefix.Prefix.Family, InterfaceLuid: route.InterfaceLuid}
		if err := windows.GetIpInterfaceEntry(&row); err != nil || row.Connected == 0 {
			continue
		}
		metric := uint64(route.Metric) + uint64(row.Metric)
		if old, ok := best[row.Family]; !ok || metric < old.metric {
			best[row.Family] = choice{row, metric}
		}
	}
	// Cover both families on each outbound adapter. An IPv6 default route may
	// appear later without an adapter change (RA, network switch, or resume).
	seen := map[forwardingEntry]bool{}
	var result []windows.MibIpInterfaceRow
	for _, selected := range best {
		for _, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
			key := forwardingEntry{selected.row.InterfaceLuid, family}
			if seen[key] {
				continue
			}
			seen[key] = true
			row := windows.MibIpInterfaceRow{Family: family, InterfaceLuid: key.LUID}
			if windows.GetIpInterfaceEntry(&row) == nil {
				result = append(result, row)
			}
		}
	}
	return result, nil
}

func CheckForwarding(manage bool) error {
	if manage {
		return nil
	}
	rows, err := defaultForwardingInterfaces()
	if err != nil {
		return fmt.Errorf("checking Windows forwarding: %w", err)
	}
	for _, row := range rows {
		if row.ForwardingEnabled != 0 {
			adapter, _ := net.InterfaceByIndex(int(row.InterfaceIndex))
			name := fmt.Sprintf("interface %d", row.InterfaceIndex)
			if adapter != nil {
				name = adapter.Name
			}
			return fmt.Errorf("IP forwarding on %s can loop TUN traffic; set routing.manage_forwarding = true to pause it during routing and restore it afterward, or disable forwarding manually", name)
		}
	}
	return nil
}

func setForwarding(row *windows.MibIpInterfaceRow, enabled uint8) error {
	row.ForwardingEnabled = enabled
	if row.Family == windows.AF_INET {
		row.SitePrefixLength = 0
	}
	code, _, _ := windows.NewLazySystemDLL("iphlpapi.dll").NewProc("SetIpInterfaceEntry").Call(uintptr(unsafe.Pointer(row)))
	if code != 0 {
		return syscall.Errno(code)
	}
	return nil
}

func saveForwarding(state forwardingState) error {
	b, err := json.Marshal(state)
	if err != nil {
		return err
	}
	p := forwardingPath()
	if err = os.WriteFile(p+".tmp", b, 0600); err != nil {
		return err
	}
	for deadline := time.Now().Add(3 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		err = os.Rename(p+".tmp", p)
		if err == nil || time.Now().After(deadline) {
			return err
		}
	}
}

func readForwarding() ([]byte, error) {
	p, _ := windows.UTF16PtrFromString(forwardingPath())
	h, err := windows.CreateFile(p, windows.GENERIC_READ, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE, nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(h), forwardingPath())
	defer file.Close()
	return io.ReadAll(file)
}

// Called only while holding forwarding.lock. A mismatched lease belongs to a
// newer service instance and must never be restored by an older watchdog.
func restoreForwarding(id string) error {
	b, err := readForwarding()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state forwardingState
	if err = json.Unmarshal(b, &state); err != nil {
		return err
	}
	if id != "" && state.ID != id {
		return nil
	}
	var failures []error
	for _, entry := range state.Entries {
		row := windows.MibIpInterfaceRow{Family: entry.Family, InterfaceLuid: entry.LUID}
		if err := windows.GetIpInterfaceEntry(&row); err != nil {
			failures = append(failures, err)
			continue
		}
		if row.ForwardingEnabled == 0 {
			if err := setForwarding(&row, 1); err != nil {
				failures = append(failures, err)
			}
		}
	}
	if err := errors.Join(failures...); err != nil {
		return fmt.Errorf("restoring Windows forwarding: %w", err)
	}
	return os.Remove(forwardingPath())
}

func beginForwarding(manage bool) (*forwardingLease, error) {
	h, err := forwardingLock()
	if err != nil {
		return nil, err
	}
	l := &forwardingLease{lock: h, manage: manage}
	if err = restoreForwarding(""); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	if !manage {
		if err = CheckForwarding(false); err != nil {
			windows.CloseHandle(h)
			return nil, err
		}
		return l, nil
	}
	var created, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(windows.CurrentProcess(), &created, &exit, &kernel, &user); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	random := make([]byte, 16)
	if _, err = rand.Read(random); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	l.state = forwardingState{ID: hex.EncodeToString(random), PID: uint32(os.Getpid()), Created: created.Nanoseconds()}
	if err = saveForwarding(l.state); err != nil {
		windows.CloseHandle(h)
		return nil, err
	}
	exe, err := os.Executable()
	if err != nil {
		l.close()
		return nil, err
	}
	cmd := exec.Command(exe, "router-watchdog", l.state.ID)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if err = cmd.Start(); err != nil {
		l.close()
		return nil, err
	}
	_ = cmd.Process.Release() // Survives a killed/crashed service process.
	if err = l.ensure(); err != nil {
		l.close()
		return nil, err
	}
	return l, nil
}

func (l *forwardingLease) ensure() error {
	rows, err := defaultForwardingInterfaces()
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.ForwardingEnabled == 0 {
			continue
		}
		if !l.manage {
			return CheckForwarding(false)
		}
		entry := forwardingEntry{row.InterfaceLuid, row.Family}
		found := false
		for _, saved := range l.state.Entries {
			if saved == entry {
				found = true
				break
			}
		}
		if !found {
			l.state.Entries = append(l.state.Entries, entry)
			// Persist the original enabled state BEFORE changing the interface.
			if err = saveForwarding(l.state); err != nil {
				return err
			}
		}
		if err = setForwarding(&row, 0); err != nil {
			return fmt.Errorf("pausing Windows forwarding: %w", err)
		}
	}
	return nil
}

func (l *forwardingLease) close() error {
	err := restoreForwarding(l.state.ID)
	windows.CloseHandle(l.lock)
	return err
}

func recoverForwarding() error {
	lock, err := forwardingLock()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	return restoreForwarding("")
}

func WatchForwarding(id string) error {
	if !Admin() {
		return fmt.Errorf("forwarding recovery requires administrator rights")
	}
	b, err := readForwarding()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var state forwardingState
	if err = json.Unmarshal(b, &state); err != nil {
		return err
	}
	if state.ID != id {
		return nil
	}
	h, err := windows.OpenProcess(windows.SYNCHRONIZE|windows.PROCESS_QUERY_LIMITED_INFORMATION, false, state.PID)
	if err == nil {
		var created, exit, kernel, user windows.Filetime
		err = windows.GetProcessTimes(h, &created, &exit, &kernel, &user)
		if err == nil && created.Nanoseconds() == state.Created {
			_, err = windows.WaitForSingleObject(h, windows.INFINITE)
		}
		windows.CloseHandle(h)
	} else if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
		err = nil
	}
	if err != nil {
		return err
	}
	lock, err := forwardingLock()
	if err != nil {
		return err
	}
	defer windows.CloseHandle(lock)
	current, err := readForwarding()
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	var latest forwardingState
	if err = json.Unmarshal(current, &latest); err != nil {
		return err
	}
	if latest.ID != id {
		return nil
	}
	err = restoreForwarding(id)
	if err != nil {
		writeStatus(false, err.Error())
	} else {
		writeStatus(false, "Routing service exited; use vpn up to restore routing")
	}
	return err
}
