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
type Server struct {
	cmd      *exec.Cmd
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
		"auth-401": `respond: { status: 401, body: { inline: { code: NotAuthenticated, message: simulated auth failure } } }`,
		"auth-403": `respond: { status: 403, body: { inline: { code: NotAuthorizedOrNotFound, message: simulated forbidden } } }`,
		"key-gone-404": `respond: { status: 404, body: { inline: { code: NotFound, message: simulated deleted key } } }`,
		"throttled-429": `respond: { status: 429, headers: { Retry-After: "1" }, body: { inline: { code: TooManyRequests, message: simulated throttling } } }`,
		"outage-500":   `respond: { status: 500, body: { inline: { code: InternalServerError, message: simulated outage } } }`,
		"unavailable-503": `respond: { status: 503, body: { inline: { code: ServiceUnavailable, message: simulated maintenance } } }`,
		"slow-500-3s":  `respond: { status: 500, latency_ms: 3000, body: { inline: { code: InternalServerError, message: slow failure } } }`,
		// 45s drop vs the plugin's 30s deadline: the plugin must hit its own
		// timeout first, which is the boundary under test
		"hang": `respond: { behavior: timeout, latency_ms: 45000 }`,
	}
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

	var prof bytes.Buffer
	for name, respond := range manifestProfiles() {
		fmt.Fprintf(&prof, "      %s:\n        description: adversarial injection %s\n        rules:\n          - match: { path: /20180608/** }\n            %s\n", name, name, respond)
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
%s`, port, filepath.ToSlash(adapterDir), prof.String())
	manifestPath := filepath.Join(dir, "stunt.yaml")
	if err := os.WriteFile(manifestPath, []byte(manifest), 0o644); err != nil {
		os.RemoveAll(dir)
		return nil, err
	}

	cmd := exec.Command(bin, "up", "--manifest", manifestPath)
	cmd.Dir = dir
	// stunt logs to stdout; keep it out of the test output but wired for debugging
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		os.RemoveAll(dir)
		return nil, fmt.Errorf("starting stunt: %w", err)
	}

	s := &Server{
		cmd: cmd,
		dir: dir,
		hc:  &http.Client{Timeout: 10 * time.Second},
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
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("stunt did not write a usable runtime file at %s", runtimePath)
		}
		// the process may have died with a manifest error; surface that, not a timeout
		if cmd.ProcessState != nil {
			return nil, fmt.Errorf("stunt up exited early: %v", cmd.ProcessState)
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
		if time.Now().After(deadline) {
			return nil, errors.New("stunt dashboard never became ready")
		}
		time.Sleep(100 * time.Millisecond)
	}
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
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_ = s.cmd.Wait()
	}
	return os.RemoveAll(s.dir)
}
