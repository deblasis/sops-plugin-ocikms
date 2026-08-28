// Package ocisim runs a stunt-backed OCI KMS stand-in for the plugin's
// adversarial tests: it boots the oci-kms-style adapter on a loopback port
// and flips failure modes through stunt's dashboard HTTP API, so Go tests
// drive injection without shelling out per scenario.
//
// Requires the stunt binary (go install stuntapi.com/stunt/cmd/stunt@latest),
// found via STUNT_BIN or PATH. Tests that cannot find it should skip.
package ocisim

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"time"
)

// Key OCIDs the simulator knows; any other key id is a 404.
const (
	Key1 = "ocid1.key.oc1.sim-region.simvault.simkey1"
	Key2 = "ocid1.key.oc1.sim-region.simvault.simkey2"
)

// bootBudget bounds server startup; the adapter is small, so this is generous.
const bootBudget = 30 * time.Second

// Server is a running `stunt up` serving the OCI KMS adapter.
//
// Profiles are service-global server state: every plugin session pointed at
// Endpoint() shares the active failure mode, so concurrent test sessions
// would cross-inject. The suite is serial by design; parallel tests must
// each Start() their own Server.
type Server struct {
	cmd      *exec.Cmd
	done     chan struct{}
	dir      string
	endpoint string
	dashURL  string
	token    string
	hc       *http.Client
}

// AdapterDir locates the checked-in adapter relative to this source file, so
// the harness works regardless of the test's working directory.
func AdapterDir() (string, error) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		return "", errors.New("cannot locate ocisim source dir")
	}
	return filepath.Join(filepath.Dir(thisFile), "adapter"), nil
}

// manifestProfiles are the manifest-level rule-bundle profiles: plain status
// and timing injections that intercept every /20180608 call pre-dispatch.
// Stateful or raw-body modes (flap, garbage, oversized) live in the adapter.
func manifestProfiles() map[string]string {
	return map[string]string{
		"auth-401":        `respond: { status: 401, body: { inline: { code: NotAuthenticated, message: simulated auth failure } } }`,
		"auth-403":        `respond: { status: 403, body: { inline: { code: NotAuthorizedOrNotFound, message: simulated forbidden } } }`,
		"key-gone-404":    `respond: { status: 404, body: { inline: { code: NotFound, message: simulated deleted key } } }`,
		"throttled-429":   `respond: { status: 429, headers: { Retry-After: "1" }, body: { inline: { code: TooManyRequests, message: simulated throttling } } }`,
		"outage-500":      `respond: { status: 500, body: { inline: { code: InternalServerError, message: simulated outage } } }`,
		"unavailable-503": `respond: { status: 503, body: { inline: { code: ServiceUnavailable, message: simulated maintenance } } }`,
		"slow-500-3s":     `respond: { status: 500, latency_ms: 3000, body: { inline: { code: InternalServerError, message: slow failure } } }`,
		// 45s drop vs the plugin's 30s deadline: the plugin must hit its own
		// timeout first, which is the boundary under test
		"hang": `respond: { behavior: timeout, latency_ms: 45000 }`,
	}
}

// exeSuffix matches the platform's executable naming for built binaries.
func exeSuffix() string {
	if runtime.GOOS == "windows" {
		return ".exe"
	}
	return ""
}

// Start boots the simulator: a temp manifest dir, `stunt up` in the
// foreground of a child process, then readiness via the runtime file stunt
// writes (dashboard URL + token + listen addresses).
func Start() (*Server, error) {
	bin := os.Getenv("STUNT_BIN")
	if bin == "" {
		var err error
		bin, err = exec.LookPath("stunt")
		if err != nil {
			return nil, errors.New("stunt binary not found (set STUNT_BIN or go install stuntapi.com/stunt/cmd/stunt@latest)")
		}
	}
	adapterDir, err := AdapterDir()
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "ocisim-*")
	if err != nil {
		return nil, err
	}

	// sorted so the generated manifest is byte-identical across runs; the
	// Windows drive colon is exactly the kind of plain-scalar trap YAML
	// quoting exists for
	names := make([]string, 0)
	for name := range manifestProfiles() {
		names = append(names, name)
	}
	sort.Strings(names)
	var prof bytes.Buffer
	for _, name := range names {
		fmt.Fprintf(&prof, "      %s:\n        description: adversarial injection %s\n        rules:\n          - match: { path: /20180608/** }\n            %s\n", name, name, manifestProfiles()[name])
	}
	// stunt rejects base_port 0, so borrow an OS-assigned port and hand it
	// over; the tiny close-to-bind window is the usual testing compromise
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		os.RemoveAll(dir)
		return nil, err
	}
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	manifest := fmt.Sprintf(`version: 1
rng_seed: 7
network:
  mode: port
  base_port: %d
services:
  ocikms:
    adapter: %s
    profiles:
%s`, port, strconv.Quote(filepath.ToSlash(adapterDir)), prof.String())
	manifestPath := filepath.Join(dir, "stunt.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	cmd := exec.Command(bin, "up", "--manifest", manifestPath)
	cmd.Dir = dir
	// buffered, not discarded: a boot failure must explain itself
	var bootLog syncBuffer
	bootLog.b.Grow(4096)
	cmd.Stdout = &bootLog
	cmd.Stderr = &bootLog
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("starting stunt: %w", err)
	}
	// ProcessState stays nil until Wait, so the poll loop cannot see an early
	// exit on its own; a Wait goroutine closes done the moment it happens
	var waitErr error
	done := make(chan struct{})
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()

	s := &Server{
		cmd:  cmd,
		done: done,
		dir:  dir,
		hc:   &http.Client{Timeout: 10 * time.Second},
	}
	// if anything below fails, do not leak the process
	booted := false
	defer func() {
		if !booted {
			s.Close()
		}
	}()

	runtimePath := filepath.Join(dir, ".stunt", "runtime", "up.json")
	deadline := time.Now().Add(bootBudget)
	var rt struct {
		Addresses      []string `json:"addresses"`
		DashboardURL   string   `json:"dashboard_url"`
		DashboardToken string   `json:"dashboard_token"`
	}
	for {
		data, err := os.ReadFile(runtimePath)
		if err == nil {
			if err := json.Unmarshal(data, &rt); err == nil && len(rt.Addresses) > 0 && rt.DashboardURL != "" {
				break
			}
		}
		select {
		case <-done:
			return nil, fmt.Errorf("stunt up exited during boot: %v\n%s", waitErr, bootLog.String())
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("stunt did not write a usable runtime file at %s\n%s", runtimePath, bootLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
	s.endpoint = rt.Addresses[0]
	s.dashURL = rt.DashboardURL
	s.token = rt.DashboardToken

	// readiness: the dashboard answers once serving; a listening-but-not-ready
	// crypto port would flake the first test request
	for {
		req, _ := http.NewRequest(http.MethodGet, s.dashURL+"/api/profile", nil)
		req.Header.Set("X-Stunt-Token", s.token)
		res, err := s.hc.Do(req)
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				booted = true
				return s, nil
			}
		}
		select {
		case <-done:
			return nil, fmt.Errorf("stunt up exited during boot: %v\n%s", waitErr, bootLog.String())
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("stunt dashboard never became ready\n%s", bootLog.String())
		}
		time.Sleep(100 * time.Millisecond)
	}
}

// syncBuffer collects the child's output. exec.Cmd copies stdout and stderr
// from two goroutines, and the harness reads only after Wait completes, but
// the mutex keeps that contract local instead of load-bearing.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Endpoint is the crypto endpoint to put in the plugin config's
// crypto_endpoint field; the plugin validates nothing about its shape.
func (s *Server) Endpoint() string { return s.endpoint }

// Activate switches the simulator into a failure mode. Profile names are the
// manifest bundles (auth-401, auth-403, key-gone-404, throttled-429,
// outage-500, unavailable-503, slow-500-3s, hang) and the adapter modes
// (flap, garbage, oversized). Runtime-only: Close discards the world.
func (s *Server) Activate(profile string) error {
	// nil-safe for callers that hold a Start() failure: tests skip instead
	if s == nil {
		return errors.New("ocisim: no server (stunt unavailable)")
	}
	return s.postProfile(map[string]string{"name": profile, "service": "ocikms"})
}

// Deactivate returns the simulator to healthy behavior.
func (s *Server) Deactivate() error {
	if s == nil {
		return errors.New("ocisim: no server (stunt unavailable)")
	}
	return s.postProfile(map[string]string{"name": ""})
}

// Reset wipes the ocikms service state via the dashboard's
// /api/state/<service>/reset endpoint, the same call `stunt reset ocikms`
// makes: collections and KV (flap parity, the seq counter, stored blobs) are
// cleared server-side. The adapter complements this: it re-materializes its
// seed keys lazily, and it embeds a per-world generation in ciphertext names
// that reset re-mints, so pre-reset ciphertexts can never decrypt afterwards
// (404) even if a KV entry survived the wipe, and the rewound seq cannot
// collide with old names. Active profiles are runtime activation state, not
// adapter state, and survive; pair with Deactivate when a test needs both.
func (s *Server) Reset() error {
	if s == nil {
		return errors.New("ocisim: no server (stunt unavailable)")
	}
	req, err := http.NewRequest(http.MethodPost, s.dashURL+"/api/state/ocikms/reset", nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Stunt-Token", s.token)
	res, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("dashboard state reset: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("state reset rejected (%d): %s", res.StatusCode, msg)
	}
	return nil
}

func (s *Server) postProfile(payload map[string]string) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, s.dashURL+"/api/profile", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("X-Stunt-Token", s.token)
	req.Header.Set("Content-Type", "application/json")
	res, err := s.hc.Do(req)
	if err != nil {
		return fmt.Errorf("dashboard profile call: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(res.Body)
		return fmt.Errorf("profile %v rejected (%d): %s", payload, res.StatusCode, msg)
	}
	return nil
}

// Close kills the stunt process and drops its state directory.
func (s *Server) Close() error {
	if s == nil {
		return nil
	}
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		// the boot goroutine owns Wait; a second Wait here races on Cmd
		// internals, so just wait for it to finish reaping
		<-s.done
	}
	return os.RemoveAll(s.dir)
}
