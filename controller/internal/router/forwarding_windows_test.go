package router

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"testing"

	"golang.org/x/sys/windows"
)

func TestRestoreForwardingInterface(t *testing.T) {
	for _, tc := range []struct {
		name                string
		getErrors           []error
		enabled             uint8
		setError, wantError error
		wantGets, wantSets  int
	}{
		{name: "removed adapter", getErrors: []error{windows.ERROR_FILE_NOT_FOUND}, wantGets: 1},
		{name: "removed address family", getErrors: []error{windows.ERROR_NOT_FOUND}, wantGets: 1},
		{name: "wrapped missing family", getErrors: []error{fmt.Errorf("lookup: %w", windows.ERROR_NOT_FOUND)}, wantGets: 1},
		{name: "already restored", enabled: 1, wantGets: 1},
		{name: "restore existing interface", wantGets: 1, wantSets: 1},
		{name: "lookup denied", getErrors: []error{windows.ERROR_ACCESS_DENIED}, wantError: windows.ERROR_ACCESS_DENIED, wantGets: 1},
		{name: "write denied", setError: windows.ERROR_ACCESS_DENIED, wantError: windows.ERROR_ACCESS_DENIED, wantGets: 1, wantSets: 1},
		{name: "adapter vanishes during restore", getErrors: []error{nil, windows.ERROR_FILE_NOT_FOUND}, setError: windows.ERROR_NOT_FOUND, wantGets: 2, wantSets: 1},
		{name: "family vanishes during restore", getErrors: []error{nil, windows.ERROR_NOT_FOUND}, setError: windows.ERROR_NOT_FOUND, wantGets: 2, wantSets: 1},
		{name: "live interface restore error remains visible", setError: windows.ERROR_NOT_FOUND, wantError: windows.ERROR_NOT_FOUND, wantGets: 2, wantSets: 1},
		{name: "failed disappearance verification stays visible", getErrors: []error{nil, windows.ERROR_ACCESS_DENIED}, setError: windows.ERROR_NOT_FOUND, wantError: windows.ERROR_ACCESS_DENIED, wantGets: 2, wantSets: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entry := forwardingEntry{LUID: 123, Family: windows.AF_INET6}
			gets, sets := 0, 0
			get := func(row *windows.MibIpInterfaceRow) error {
				if row.InterfaceLuid != entry.LUID || row.Family != entry.Family {
					t.Fatal("wrong interface queried")
				}
				gets++
				row.ForwardingEnabled = tc.enabled
				if gets <= len(tc.getErrors) {
					return tc.getErrors[gets-1]
				}
				return nil
			}
			set := func(row *windows.MibIpInterfaceRow, enabled uint8) error {
				sets++
				if row.InterfaceLuid != entry.LUID || row.Family != entry.Family || enabled != 1 {
					t.Fatal("wrong forwarding restoration")
				}
				return tc.setError
			}
			err := restoreForwardingInterface(entry, get, set)
			if !errors.Is(err, tc.wantError) {
				t.Fatalf("got %v, want %v", err, tc.wantError)
			}
			if gets != tc.wantGets || sets != tc.wantSets {
				t.Fatalf("lookup/write count = %d/%d, want %d/%d", gets, sets, tc.wantGets, tc.wantSets)
			}
		})
	}
}

func TestRestoreForwardingRejectsInvalidIdentity(t *testing.T) {
	for _, entry := range []forwardingEntry{{LUID: 0, Family: windows.AF_INET}, {LUID: 123, Family: 0}} {
		err := restoreForwardingInterface(entry, func(*windows.MibIpInterfaceRow) error { t.Fatal("invalid identity reached Windows"); return nil }, nil)
		if err == nil {
			t.Fatal("accepted invalid saved identity")
		}
	}
}

func TestForwardingJournalPartialRecoveryAndRetry(t *testing.T) {
	entries := []forwardingEntry{{LUID: 1, Family: windows.AF_INET}, {LUID: 2, Family: windows.AF_INET6}, {LUID: 3, Family: windows.AF_INET}}
	state := forwardingState{ID: "lease", PID: 123, Created: 456, Entries: entries}
	body, _ := json.Marshal(state)
	removed, saves := 0, 0
	read := func() ([]byte, error) { return body, nil }
	save := func(next forwardingState) error {
		saves++
		if next.ID != state.ID || next.PID != state.PID || next.Created != state.Created {
			t.Fatal("lease owner changed")
		}
		if !reflect.DeepEqual(next.Entries, entries[1:2]) {
			t.Fatalf("completed entries retained: %v", next.Entries)
		}
		body, _ = json.Marshal(next)
		return nil
	}
	remove := func() error { removed++; return nil }
	var visited []forwardingEntry
	err := restoreForwardingJournal("lease", read, save, remove, func(entry forwardingEntry) error {
		visited = append(visited, entry)
		if entry == entries[1] {
			return windows.ERROR_ACCESS_DENIED
		}
		return nil // Includes a confirmed missing interface: no remaining setting.
	})
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || removed != 0 || saves != 1 || !reflect.DeepEqual(visited, entries) {
		t.Fatalf("partial recovery failed: %v, visited=%v saves=%d removed=%d", err, visited, saves, removed)
	}
	visited = nil
	err = restoreForwardingJournal("lease", read, save, remove, func(entry forwardingEntry) error { visited = append(visited, entry); return nil })
	if err != nil || removed != 1 || saves != 1 || !reflect.DeepEqual(visited, entries[1:2]) {
		t.Fatalf("retry repeated completed work: %v, %v", err, visited)
	}
}

func TestForwardingJournalOwnershipAndFailures(t *testing.T) {
	state := forwardingState{ID: "new-lease", Entries: []forwardingEntry{{LUID: 1, Family: windows.AF_INET}}}
	valid, _ := json.Marshal(state)
	for _, tc := range []struct {
		name, id                                                   string
		body                                                       []byte
		readError, restoreError, saveError, removeError, wantError error
		wantRestores, wantSaves, wantRemoves                       int
	}{
		{name: "old watchdog cannot restore new lease", id: "old-lease", body: valid},
		{name: "missing journal", readError: os.ErrNotExist},
		{name: "unreadable journal", readError: windows.ERROR_ACCESS_DENIED, wantError: windows.ERROR_ACCESS_DENIED},
		{name: "successful recovery removes journal", body: valid, wantRestores: 1, wantRemoves: 1},
		{name: "completed journal removal fails", body: valid, removeError: windows.ERROR_ACCESS_DENIED, wantError: windows.ERROR_ACCESS_DENIED, wantRestores: 1, wantRemoves: 1},
		{name: "failed progress save stays visible", body: valid, restoreError: windows.ERROR_ACCESS_DENIED, saveError: windows.ERROR_DISK_FULL, wantError: windows.ERROR_DISK_FULL, wantRestores: 1, wantSaves: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			restores, saves, removes := 0, 0, 0
			err := restoreForwardingJournal(tc.id,
				func() ([]byte, error) { return tc.body, tc.readError },
				func(forwardingState) error { saves++; return tc.saveError },
				func() error { removes++; return tc.removeError },
				func(forwardingEntry) error { restores++; return tc.restoreError })
			if !errors.Is(err, tc.wantError) || restores != tc.wantRestores || saves != tc.wantSaves || removes != tc.wantRemoves {
				t.Fatalf("got err=%v operations=%d/%d/%d", err, restores, saves, removes)
			}
			if tc.restoreError != nil && !errors.Is(err, tc.restoreError) {
				t.Fatal("original restoration error was lost")
			}
		})
	}
	t.Run("corrupt journal preserved", func(t *testing.T) {
		called := false
		err := restoreForwardingJournal("", func() ([]byte, error) { return []byte("{bad"), nil },
			func(forwardingState) error { called = true; return nil }, func() error { called = true; return nil }, func(forwardingEntry) error { called = true; return nil })
		if err == nil || called {
			t.Fatal("corrupt journal caused network or state changes")
		}
	})
}
