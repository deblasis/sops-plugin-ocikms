package ociconfig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// isolateHome redirects both HOME and USERPROFILE: the SDK resolves the home
// directory via HOME on POSIX and USERPROFILE on Windows, so isolating only
// HOME lets the real ~/.oci/config leak into Windows test runs.
func isolateHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv(HomeEnv, home)
	t.Setenv(UserProfileEnv, home)
	return home
}

// writeTempRSAKey writes an unencrypted PKCS#1 RSA private key to a temp file.
func writeTempRSAKey(t *testing.T, dir string) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	pemBlock := &pem.Block{Type: "RSA PRIVATE KEY", Bytes: keyBytes}
	pemData := pem.EncodeToMemory(pemBlock)
	path := filepath.Join(dir, "oci-test-private-key.pem")
	if err := os.WriteFile(path, pemData, 0600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return path
}

// writeOCIConfig writes a minimal ~/.oci/config style file.
func writeOCIConfig(t *testing.T, path string, profile string, user string, tenancy string, region string, fingerprint string, keyFile string) {
	t.Helper()
	content := strings.Join([]string{
		"[" + profile + "]",
		"user=" + user,
		"fingerprint=" + fingerprint,
		"key_file=" + keyFile,
		"tenancy=" + tenancy,
		"region=" + region,
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// clearOCIEnv clears OCI SDK environment variables to prevent interference
func clearOCIEnv(t *testing.T) {
	t.Helper()
	envVars := []string{
		OCITenancyOCID,
		OCIUserOCID,
		OCIRegion,
		OCIFingerprint,
		OCIPrivateKeyPath,
	}
	for _, env := range envVars {
		t.Setenv(env, "")
	}
}

// clearCLIOCIEnv clears OCI CLI environment variables to prevent interference.
// The env provider treats an empty-but-set variable as set, so these must be
// truly unset, then restored.
func clearCLIOCIEnv(t *testing.T) {
	t.Helper()
	envVars := []string{
		OCICLITenancy,
		OCICLIUser,
		OCICLIRegion,
		OCICLIFingerprint,
		OCICLIKeyFile,
	}
	for _, env := range envVars {
		old, wasSet := os.LookupEnv(env)
		os.Unsetenv(env)
		if wasSet {
			t.Cleanup(func() { os.Setenv(env, old) })
		}
	}
}

// disableIPProvider disables Instance Principal provider in tests
func disableIPProvider(t *testing.T) {
	t.Helper()
	old := newIPProvider
	t.Cleanup(func() { newIPProvider = old })
	newIPProvider = func() (common.ConfigurationProvider, error) {
		return nil, fmt.Errorf("ip disabled in tests")
	}
}

func TestConfigurationProvider_OCI_CLI_Env(t *testing.T) {
	// Disable IP network path in tests by overriding factory
	disableIPProvider(t)
	// Isolate HOME/USERPROFILE to avoid default file provider interference
	isolateHome(t)

	// Generate key
	keyDir := t.TempDir()
	keyPath := writeTempRSAKey(t, keyDir)

	// Set OCI_CLI_* envs
	t.Setenv(OCICLITenancy, "ocid1.tenancy.oc1..exampletenancy")
	t.Setenv(OCICLIUser, "ocid1.user.oc1..exampleuser")
	t.Setenv(OCICLIRegion, "us-ashburn-1")
	t.Setenv(OCICLIFingerprint, "aa:bb:cc:dd")
	t.Setenv(OCICLIKeyFile, keyPath)

	// Ensure other providers are not set by accident
	// Native SDK env provider uses lower-case suffixes with prefix OCI_
	clearOCIEnv(t)

	prov, err := ConfigurationProvider()
	if err != nil {
		t.Fatal(err)
	}

	if tenancy, err := prov.TenancyOCID(); err != nil || tenancy != "ocid1.tenancy.oc1..exampletenancy" {
		t.Fatalf("tenancy = %q, %v", tenancy, err)
	}
	if user, err := prov.UserOCID(); err != nil || user != "ocid1.user.oc1..exampleuser" {
		t.Fatalf("user = %q, %v", user, err)
	}
	if region, err := prov.Region(); err != nil || region != "us-ashburn-1" {
		t.Fatalf("region = %q, %v", region, err)
	}
	if fp, err := prov.KeyFingerprint(); err != nil || fp != "aa:bb:cc:dd" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}

func TestConfigurationProvider_OCI_Env(t *testing.T) {
	disableIPProvider(t)
	isolateHome(t)

	keyDir := t.TempDir()
	keyPath := writeTempRSAKey(t, keyDir)

	// SDK env provider expects lower-case suffixes
	t.Setenv(OCITenancyOCID, "ocid1.tenancy.oc1..ten")
	t.Setenv(OCIUserOCID, "ocid1.user.oc1..usr")
	t.Setenv(OCIRegion, "eu-frankfurt-1")
	t.Setenv(OCIFingerprint, "11:22:33:44")
	t.Setenv(OCIPrivateKeyPath, keyPath)

	// Ensure CLI envs are not set
	clearCLIOCIEnv(t)

	prov, err := ConfigurationProvider()
	if err != nil {
		t.Fatal(err)
	}

	if tenancy, err := prov.TenancyOCID(); err != nil || tenancy != "ocid1.tenancy.oc1..ten" {
		t.Fatalf("tenancy = %q, %v", tenancy, err)
	}
	if user, err := prov.UserOCID(); err != nil || user != "ocid1.user.oc1..usr" {
		t.Fatalf("user = %q, %v", user, err)
	}
	if region, err := prov.Region(); err != nil || region != "eu-frankfurt-1" {
		t.Fatalf("region = %q, %v", region, err)
	}
	if fp, err := prov.KeyFingerprint(); err != nil || fp != "11:22:33:44" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}

func TestConfigurationProvider_FileViaEnv(t *testing.T) {
	disableIPProvider(t)
	isolateHome(t)

	d := t.TempDir()
	keyPath := writeTempRSAKey(t, d)
	cfgPath := filepath.Join(d, "config")
	writeOCIConfig(t, cfgPath, "DEFAULT", "ocid1.user.oc1..fileusr", "ocid1.tenancy.oc1..fileten", "uk-london-1", "ff:ee:dd:cc", keyPath)

	// Point to config via env
	t.Setenv(OCICLIConfigFile, cfgPath)
	// Explicit profile not required; default is DEFAULT

	// Ensure env-based providers are not set
	clearCLIOCIEnv(t)
	clearOCIEnv(t)

	prov, err := ConfigurationProvider()
	if err != nil {
		t.Fatal(err)
	}

	if tenancy, err := prov.TenancyOCID(); err != nil || tenancy != "ocid1.tenancy.oc1..fileten" {
		t.Fatalf("tenancy = %q, %v", tenancy, err)
	}
	if user, err := prov.UserOCID(); err != nil || user != "ocid1.user.oc1..fileusr" {
		t.Fatalf("user = %q, %v", user, err)
	}
	if region, err := prov.Region(); err != nil || region != "uk-london-1" {
		t.Fatalf("region = %q, %v", region, err)
	}
	if fp, err := prov.KeyFingerprint(); err != nil || fp != "ff:ee:dd:cc" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}

// hostDefaultOCIConfigExists mirrors the SDK's getHomeFolder: user.Current()
// first, HOME/USERPROFILE only as fallback. When the OS account already has a
// real ~/.oci/config, the default-file slot cannot be env-isolated (the SDK
// ignores both env vars on Windows), so the chain test below must step aside.
func hostDefaultOCIConfigExists() bool {
	home := ""
	if u, err := user.Current(); err == nil {
		home = u.HomeDir
	} else if h := os.Getenv(HomeEnv); h != "" {
		home = h
	} else {
		home = os.Getenv(UserProfileEnv)
	}
	if home == "" {
		return false
	}
	_, err := os.Stat(filepath.Join(home, ".oci", "config"))
	return err == nil
}

func TestConfigurationProvider_DefaultFileFallback(t *testing.T) {
	disableIPProvider(t)
	if hostDefaultOCIConfigExists() {
		t.Skip("host account has a real ~/.oci/config; the SDK resolves it via user.Current(), which ignores HOME/USERPROFILE isolation")
	}

	// the fix for the PR's Windows isolation bug: BOTH home vars point at
	// the temp home, and the chain is exercised end to end
	home := isolateHome(t)

	ociDir := filepath.Join(home, ".oci")
	if err := os.MkdirAll(ociDir, 0700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	keyPath := writeTempRSAKey(t, ociDir)
	cfgPath := filepath.Join(ociDir, "config")
	writeOCIConfig(t, cfgPath, "DEFAULT", "ocid1.user.oc1..defusr", "ocid1.tenancy.oc1..deften", "ap-tokyo-1", "00:aa:bb:cc", keyPath)

	// Ensure no env points to an explicit file and env providers are empty
	t.Setenv(OCICLIConfigFile, "")
	t.Setenv(OCICLIProfile, "")
	clearCLIOCIEnv(t)
	clearOCIEnv(t)

	// through the composed chain, not a direct file provider: proves the
	// default-file slot lands on the isolated home
	prov, err := ConfigurationProvider()
	if err != nil {
		t.Fatal(err)
	}

	if tenancy, err := prov.TenancyOCID(); err != nil || tenancy != "ocid1.tenancy.oc1..deften" {
		t.Fatalf("tenancy = %q, %v", tenancy, err)
	}
	if user, err := prov.UserOCID(); err != nil || user != "ocid1.user.oc1..defusr" {
		t.Fatalf("user = %q, %v", user, err)
	}
	if region, err := prov.Region(); err != nil || region != "ap-tokyo-1" {
		t.Fatalf("region = %q, %v", region, err)
	}
	if fp, err := prov.KeyFingerprint(); err != nil || fp != "00:aa:bb:cc" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}

// TestConfigurationProvider_ConfigFileSlotAlwaysResolvable runs on every
// machine regardless of a host ~/.oci/config: the explicit-file slot (step 3
// of the chain) is what a real deployment sets via OCI_CLI_CONFIG_FILE.
func TestConfigurationProvider_ConfigFileSlotWithProfile(t *testing.T) {
	disableIPProvider(t)
	isolateHome(t)

	d := t.TempDir()
	keyPath := writeTempRSAKey(t, d)
	cfgPath := filepath.Join(d, "config")
	writeOCIConfig(t, cfgPath, "CUSTOM", "ocid1.user.oc1..profusr", "ocid1.tenancy.oc1..proften", "ca-toronto-1", "99:88:77:66", keyPath)

	t.Setenv(OCICLIConfigFile, cfgPath)
	t.Setenv(OCICLIProfile, "CUSTOM")
	clearCLIOCIEnv(t)
	clearOCIEnv(t)

	prov, err := ConfigurationProvider()
	if err != nil {
		t.Fatal(err)
	}
	if tenancy, err := prov.TenancyOCID(); err != nil || tenancy != "ocid1.tenancy.oc1..proften" {
		t.Fatalf("tenancy = %q, %v", tenancy, err)
	}
	if fp, err := prov.KeyFingerprint(); err != nil || fp != "99:88:77:66" {
		t.Fatalf("fingerprint = %q, %v", fp, err)
	}
}

func TestLazyProviderDefersFactory(t *testing.T) {
	called := 0
	l := &lazyConfigurationProvider{factory: func() (common.ConfigurationProvider, error) {
		called++
		return nil, fmt.Errorf("no instance metadata")
	}}
	if called != 0 {
		t.Fatal("factory must not run at construction")
	}
	if _, err := l.TenancyOCID(); err == nil {
		t.Fatal("expected factory error")
	}
	if _, err := l.Region(); err == nil {
		t.Fatal("factory error must stick")
	}
	if called != 1 {
		t.Fatalf("factory ran %d times, want exactly once (sync.Once)", called)
	}
}

// stubIPProvider stands in for the instance-principal provider with known
// values for every method.
type stubIPProvider struct{}

func (stubIPProvider) TenancyOCID() (string, error)            { return "stub-tenancy", nil }
func (stubIPProvider) UserOCID() (string, error)               { return "stub-user", nil }
func (stubIPProvider) KeyFingerprint() (string, error)         { return "stub-fingerprint", nil }
func (stubIPProvider) Region() (string, error)                 { return "stub-region", nil }
func (stubIPProvider) KeyID() (string, error)                  { return "stub-keyid", nil }
func (stubIPProvider) PrivateRSAKey() (*rsa.PrivateKey, error) { return nil, nil }
func (stubIPProvider) AuthType() (common.AuthConfig, error)    { return common.AuthConfig{}, nil }

// TestLazyProviderDelegatesAllMethods exercises all seven delegation paths,
// not just the two the error test touches.
func TestLazyProviderDelegatesAllMethods(t *testing.T) {
	called := 0
	l := &lazyConfigurationProvider{factory: func() (common.ConfigurationProvider, error) {
		called++
		return stubIPProvider{}, nil
	}}
	if v, err := l.TenancyOCID(); err != nil || v != "stub-tenancy" {
		t.Fatalf("TenancyOCID = %q, %v", v, err)
	}
	if v, err := l.UserOCID(); err != nil || v != "stub-user" {
		t.Fatalf("UserOCID = %q, %v", v, err)
	}
	if v, err := l.KeyFingerprint(); err != nil || v != "stub-fingerprint" {
		t.Fatalf("KeyFingerprint = %q, %v", v, err)
	}
	if v, err := l.Region(); err != nil || v != "stub-region" {
		t.Fatalf("Region = %q, %v", v, err)
	}
	if v, err := l.KeyID(); err != nil || v != "stub-keyid" {
		t.Fatalf("KeyID = %q, %v", v, err)
	}
	if k, err := l.PrivateRSAKey(); err != nil || k != nil {
		t.Fatalf("PrivateRSAKey = %v, %v", k, err)
	}
	if _, err := l.AuthType(); err != nil {
		t.Fatalf("AuthType: %v", err)
	}
	if called != 1 {
		t.Fatalf("factory ran %d times, want exactly once (sync.Once)", called)
	}
}
