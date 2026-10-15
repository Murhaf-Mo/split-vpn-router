// Package api is the HTTP client to the daemon (vpnctl.py).
// All daemon mutations go through here so the CLI and tray share one
// surface. Errors include the response body when the daemon returned an
// error envelope.
package api

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"
)

type Client struct {
	BaseURL string
	HTTP    *http.Client
	Token   string
}

// Status mirrors the daemon's /api/status response.
type Status struct {
	Mode            string   `json:"mode"`
	OcPid           int      `json:"oc_pid"`
	RelayPid        int      `json:"relay_pid"`
	DaemonPid       int      `json:"daemon_pid"`
	Tun0IP          string   `json:"tun0_ip"`
	ProxyHost       string   `json:"proxy_host"`
	ConnectionState string   `json:"connection_state"`
	Error           string   `json:"error"`
	ProxyPort       int      `json:"proxy_port"`
	VPNList         ListInfo `json:"vpn_list"`
	DirectList      ListInfo `json:"direct_list"`
}

type ListInfo struct {
	Domains    int     `json:"domains"`
	Cidrs      int     `json:"cidrs"`
	URLs       int     `json:"urls"`
	Mtime      float64 `json:"mtime"`
	LastReload float64 `json:"last_reload"`
}

type ListResponse struct {
	List    string   `json:"list"`
	Entries []string `json:"entries"`
}

type ListEditResponse struct {
	List    string   `json:"list"`
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
	Skipped []string `json:"skipped"`
}

type apiError struct {
	Err string `json:"error"`
}

func New(wslIP string, pacPort int) *Client {
	return &Client{
		BaseURL: fmt.Sprintf("http://%s:%d", wslIP, pacPort),
		HTTP: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				DialContext: (&net.Dialer{Timeout: 2 * time.Second}).DialContext,
			},
		},
	}
}

// quickClient is used for the initial status probe with a short timeout so
// `vpn up` / `vpn status` don't hang for the full 8s when the daemon is down.
func (c *Client) Quick() *Client {
	cp := *c
	cp.HTTP = &http.Client{
		Timeout: 1500 * time.Millisecond,
		Transport: &http.Transport{
			DialContext: (&net.Dialer{Timeout: 800 * time.Millisecond}).DialContext,
		},
	}
	return &cp
}

func (c *Client) do(method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.BaseURL+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.Token)
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 400 {
		var ae apiError
		_ = json.Unmarshal(data, &ae)
		if ae.Err != "" {
			return fmt.Errorf("%s %s: %s", method, path, ae.Err)
		}
		return fmt.Errorf("%s %s: HTTP %d", method, path, resp.StatusCode)
	}
	if out == nil {
		return nil
	}
	if s, ok := out.(*string); ok {
		*s = string(data)
		return nil
	}
	return json.Unmarshal(data, out)
}

// ---- Status ----

func (c *Client) Status() (*Status, error) {
	var s Status
	if err := c.do("GET", "/api/status", nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// ---- Mode ----

func (c *Client) GetMode() (string, error) {
	var resp struct {
		Mode string `json:"mode"`
	}
	if err := c.do("GET", "/api/mode", nil, &resp); err != nil {
		return "", err
	}
	return resp.Mode, nil
}

func (c *Client) SetMode(mode string) error {
	return c.do("POST", "/api/mode", map[string]string{"mode": mode}, nil)
}

// ---- Lists ----

func (c *Client) ListEntries(which string) ([]string, error) {
	var resp ListResponse
	if err := c.do("GET", "/api/lists/"+which, nil, &resp); err != nil {
		return nil, err
	}
	return resp.Entries, nil
}

func (c *Client) ListAdd(which string, entries []string) (*ListEditResponse, error) {
	var r ListEditResponse
	if err := c.do("POST", "/api/lists/"+which, map[string][]string{"add": entries}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

func (c *Client) ListRemove(which string, entries []string) (*ListEditResponse, error) {
	var r ListEditResponse
	if err := c.do("POST", "/api/lists/"+which, map[string][]string{"remove": entries}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// ---- Logs ----

func (c *Client) LogTail(name string, n int) (string, error) {
	var out string
	if err := c.do("GET", fmt.Sprintf("/api/logs/%s?tail=%d", url.PathEscape(name), n), nil, &out); err != nil {
		return "", err
	}
	return out, nil
}

// ---- Misc ----

func (c *Client) Reload() error {
	return c.do("POST", "/api/reload", nil, nil)
}

func (c *Client) RestartOpenconnect() (*Status, error) {
	if err := c.Disconnect(); err != nil {
		return nil, err
	}
	return c.Connect()
}

func (c *Client) Connect() (*Status, error) {
	var s Status
	err := c.do("POST", "/api/connect", nil, &s)
	return &s, err
}
func (c *Client) Disconnect() error { return c.do("POST", "/api/disconnect", nil, nil) }
