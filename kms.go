package ocikms

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"github.com/deblasis/sops-plugin-ocikms/ociconfig"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/keymanagement"
)

// kmsAPI is the slice of the OCI KMS API the plugin uses. Tests substitute
// fakes; the real implementation talks to the crypto endpoint.
type kmsAPI interface {
	Encrypt(ctx context.Context, keyID, plaintextB64 string) (ciphertextB64 string, err error)
	Decrypt(ctx context.Context, keyID, ciphertextB64 string) (plaintextB64 string, err error)
}

// realKMS wraps a KmsCryptoClient. The Encrypt/Decrypt bodies are ported
// from getsops/sops PR #1226 (MPL-2.0), ocikms/keysource.go, minus the sops
// MasterKey bookkeeping.
type realKMS struct {
	client keymanagement.KmsCryptoClient
}

// errNoCredentials marks a failure to find any usable auth material in the
// environment/instance/config chain; classify maps it to auth_failed.
var errNoCredentials = errors.New("no usable OCI credentials in environment/instance/config chain")

func newRealKMS(ctx context.Context, cryptoEndpoint string) (*realKMS, error) {
	cfg, err := ociconfig.ConfigurationProvider()
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI configuration provider: %w", err)
	}
	// force the credential chain now so "no credentials" is an auth error,
	// not a per-request mystery
	if _, err := cfg.KeyID(); err != nil {
		return nil, fmt.Errorf("%w: %w", errNoCredentials, err)
	}
	client, err := keymanagement.NewKmsCryptoClientWithConfigurationProvider(cfg, cryptoEndpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCI KMS client: %w", err)
	}
	return &realKMS{client: client}, nil
}

func (k *realKMS) Encrypt(ctx context.Context, keyID, plaintextB64 string) (string, error) {
	res, err := k.client.Encrypt(ctx, keymanagement.EncryptRequest{
		EncryptDataDetails: keymanagement.EncryptDataDetails{
			KeyId:     common.String(keyID),
			Plaintext: common.String(plaintextB64),
		},
		RequestMetadata: common.RequestMetadata{},
	})
	if err != nil {
		return "", fmt.Errorf("failed to encrypt sops data key with OCI KMS key: %w", err)
	}
	return *res.EncryptedData.Ciphertext, nil
}

func (k *realKMS) Decrypt(ctx context.Context, keyID, ciphertextB64 string) (string, error) {
	res, err := k.client.Decrypt(ctx, keymanagement.DecryptRequest{
		DecryptDataDetails: keymanagement.DecryptDataDetails{
			Ciphertext: common.String(ciphertextB64),
			KeyId:      common.String(keyID),
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to decrypt sops data key with OCI KMS key: %w", err)
	}
	return *res.DecryptedData.Plaintext, nil
}

// blob is the JSON payload inside the wrapped key, std-base64 encoded after
// the ocikms.v1. prefix. Decrypt works from the blob alone: it carries
// everything needed to reach the key again, credentials come from the
// runtime environment.
//
// Wire-compatibility policy: ADDING fields is safe (both sides ignore
// unknown JSON fields); renaming or removing fields is not, and neither is
// any payload format change. A breaking change requires a new prefix
// (ocikms.v2), with v1 blobs still decryptable.
type blob struct {
	KeyID          string `json:"keyId"`
	CryptoEndpoint string `json:"cryptoEndpoint"`
	Region         string `json:"region"`
	CiphertextB64  string `json:"ciphertext"`
}

// KMSHandler implements protocol.Handler against OCI KMS.
type KMSHandler struct {
	// Fake replaces the network KMS with an in-process wrap (testing hook,
	// enabled by SOPS_OCIKMS_FAKE_KMS=1 in main). Fake mode always forces
	// the fake key id and endpoint, even when config carries real values,
	// so a fake blob is distinguishable by its key_ref and never
	// masquerades as a real OCID; every fake wrap also warns on stderr.
	Fake bool
	// WarnWriter receives the fake-mode warning; nil means os.Stderr.
	// Tests inject io.Discard.
	WarnWriter io.Writer
	// RequestTimeout bounds each KMS call; zero means the 30s default.
	// The SDK's own default is 60s, too long for a stalled CI run.
	RequestTimeout time.Duration
	// newClient builds the KMS shim for a crypto endpoint; swappable in
	// tests. Nil means the real client.
	newClient func(ctx context.Context, cryptoEndpoint string) (kmsAPI, error)
}

// defaultRequestTimeout bounds one backend call. The host's own request
// timeout is 30s by default, so a plugin that hangs longer just gets killed;
// answering key_unavailable at 30s is friendlier than dying silently.
const defaultRequestTimeout = 30 * time.Second

func (h *KMSHandler) timeout() time.Duration {
	if h.RequestTimeout > 0 {
		return h.RequestTimeout
	}
	return defaultRequestTimeout
}

func (h *KMSHandler) warnFake() {
	w := h.WarnWriter
	if w == nil {
		w = os.Stderr
	}
	fmt.Fprintln(w, "sops-plugin-ocikms: FAKE KMS (SOPS_OCIKMS_FAKE_KMS=1): using the in-process fake, not real OCI KMS; output is NOT encrypted")
}

func (h *KMSHandler) client(ctx context.Context, endpoint string) (kmsAPI, error) {
	if h.newClient != nil {
		return h.newClient(ctx, endpoint)
	}
	if h.Fake {
		return fakeKMS{}, nil
	}
	return newRealKMS(ctx, endpoint)
}

const (
	// ocidParts is the number of parts in an OCID, separated by ".", eg:
	// "ocid1.key.oc1.uk-london-1.aaaalgz5aacmg.aaaailjtjbkbc5ufsorrihgv2agugpfe7wrtngukihgkybqxcoozz7sbh6lq"
	ocidParts = 6

	fakeKeyID    = "ocid1.key.oc1.fake-region.fakevault.fakekey"
	fakeEndpoint = "https://fakevault-crypto.kms.fake-region.oraclecloud.com"
)

// regionFromOCID extracts the region component of a key OCID, same parse as
// the sops provider's extractRefs. Empty when the OCID does not parse: the
// crypto endpoint from config is authoritative, the region is bookkeeping.
func regionFromOCID(ocid string) string {
	parts := strings.Split(ocid, ".")
	if len(parts) != ocidParts {
		return ""
	}
	return parts[3]
}

func (h *KMSHandler) Encrypt(config map[string]any, plaintext []byte) (string, string, error) {
	if len(plaintext) == 0 {
		return "", "", &WireError{Code: CodeInvalidRequest, Message: "encrypt request has an empty plaintext"}
	}
	keyID, _ := config["key_id"].(string)
	endpoint, _ := config["crypto_endpoint"].(string)
	if h.Fake {
		keyID = fakeKeyID
		endpoint = fakeEndpoint
		h.warnFake()
	} else if keyID == "" || endpoint == "" {
		return "", "", &WireError{Code: CodeConfigError, Message: "config requires string fields key_id and crypto_endpoint"}
	}

	// a fresh client per request is fine for sops' usage (one key operation
	// per process lifetime); cache per endpoint if you ever batch
	ctx, cancel := context.WithTimeout(context.Background(), h.timeout())
	defer cancel()
	c, err := h.client(ctx, endpoint)
	if err != nil {
		return "", "", classify(err)
	}
	ctB64, err := c.Encrypt(ctx, keyID, base64.StdEncoding.EncodeToString(plaintext))
	if err != nil {
		return "", "", classify(err)
	}
	if ctB64 == "" {
		return "", "", &WireError{Code: CodeInternal, Message: "KMS returned an empty ciphertext"}
	}
	b := blob{KeyID: keyID, CryptoEndpoint: endpoint, Region: regionFromOCID(keyID), CiphertextB64: ctB64}
	payload, err := json.Marshal(b)
	if err != nil {
		return "", "", &WireError{Code: CodeInternal, Message: "marshaling wrapped blob: " + err.Error()}
	}
	return BlobPrefix + base64.StdEncoding.EncodeToString(payload), keyID, nil
}

func (h *KMSHandler) Decrypt(wrapped string) ([]byte, error) {
	b, werr := parseWrappedBlob(wrapped)
	if werr != nil {
		return nil, werr
	}

	if h.Fake {
		h.warnFake()
		plaintext, err := fakeOpen(b.KeyID, b.CiphertextB64)
		if err != nil {
			return nil, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob does not open: " + err.Error()}
		}
		return plaintext, nil
	}
	if b.CryptoEndpoint == "" {
		return nil, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob is missing cryptoEndpoint"}
	}

	ctx, cancel := context.WithTimeout(context.Background(), h.timeout())
	defer cancel()
	c, err := h.client(ctx, b.CryptoEndpoint)
	if err != nil {
		return nil, classify(err)
	}
	ptB64, err := c.Decrypt(ctx, b.KeyID, b.CiphertextB64)
	if err != nil {
		return nil, classify(err)
	}
	plaintext, err := base64.StdEncoding.DecodeString(ptB64)
	if err != nil {
		return nil, &WireError{Code: CodeInternal, Message: "KMS plaintext is not valid base64"}
	}
	return plaintext, nil
}

// parseWrappedBlob decodes the ocikms.v1 wrapped-key payload. Every parse
// failure is invalid_request: a foreign or corrupt blob is distinguishable
// from a backend failure, which is the point of the prefix.
func parseWrappedBlob(wrapped string) (blob, *WireError) {
	if !strings.HasPrefix(wrapped, BlobPrefix) {
		return blob{}, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob does not start with " + BlobPrefix}
	}
	payload, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(wrapped, BlobPrefix))
	if err != nil {
		return blob{}, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob payload is not valid base64"}
	}
	var b blob
	if err := json.Unmarshal(payload, &b); err != nil {
		return blob{}, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob payload is not valid JSON"}
	}
	if b.KeyID == "" || b.CiphertextB64 == "" {
		return blob{}, &WireError{Code: CodeInvalidRequest, Message: "wrapped blob is missing keyId or ciphertext"}
	}
	return b, nil
}

// classify maps an OCI SDK failure onto the frozen v1 codes:
// credential rejection -> auth_failed (fatal, never retried by the host);
// missing/throttled/unreachable backend -> key_unavailable; undecodable
// service input -> invalid_request; anything else is ours -> internal.
func classify(err error) *WireError {
	// errors.As, not common.IsServiceError: the call sites wrap with %w, and
	// IsServiceError is a bare type assertion that stops at the first wrap
	var se common.ServiceError
	if errors.As(err, &se) {
		msg := se.GetMessage()
		if msg == "" {
			msg = se.GetCode()
		}
		switch code := se.GetHTTPStatusCode(); {
		case code == 401 || code == 403:
			return &WireError{Code: CodeAuthFailed, Message: fmt.Sprintf("OCI KMS rejected the credentials (%d): %s", code, msg)}
		case code == 404:
			return &WireError{Code: CodeKeyUnavailable, Message: "OCI KMS key not found: " + msg}
		case code == 429:
			// throttled means temporarily unreachable; the host does not
			// retry answered requests, and this plugin owns no retries
			return &WireError{Code: CodeKeyUnavailable, Message: "OCI KMS throttled the request (429): " + msg}
		case code >= 500:
			return &WireError{Code: CodeKeyUnavailable, Message: fmt.Sprintf("OCI KMS unavailable (%d): %s", code, msg)}
		case code == 400:
			return &WireError{Code: CodeInvalidRequest, Message: "OCI KMS rejected the request (400): " + msg}
		default:
			return &WireError{Code: CodeInternal, Message: fmt.Sprintf("OCI KMS error (%d): %s", code, msg)}
		}
	}
	if errors.Is(err, errNoCredentials) {
		return &WireError{Code: CodeAuthFailed, Message: err.Error()}
	}
	var netErr net.Error
	if errors.As(err, &netErr) || errors.Is(err, context.DeadlineExceeded) {
		return &WireError{Code: CodeKeyUnavailable, Message: "OCI KMS endpoint unreachable: " + err.Error()}
	}
	return &WireError{Code: CodeInternal, Message: err.Error()}
}

// fakeKMS is the in-process stand-in used when SOPS_OCIKMS_FAKE_KMS=1. It is
// NOT cryptography: a SHA-256 keystream derived from the key id, XORed with
// the plaintext. Enough shape for protocol conformance, never for secrets.
type fakeKMS struct{}

func (fakeKMS) Encrypt(_ context.Context, keyID, plaintextB64 string) (string, error) {
	plaintext, err := base64.StdEncoding.DecodeString(plaintextB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(fakeXOR(keyID, plaintext)), nil
}

func (fakeKMS) Decrypt(_ context.Context, keyID, ciphertextB64 string) (string, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(fakeXOR(keyID, ciphertext)), nil
}

func fakeOpen(keyID, ciphertextB64 string) ([]byte, error) {
	ciphertext, err := base64.StdEncoding.DecodeString(ciphertextB64)
	if err != nil {
		return nil, err
	}
	return fakeXOR(keyID, ciphertext), nil
}

func fakeXOR(keyID string, data []byte) []byte {
	out := make([]byte, len(data))
	var ctr uint32
	n := 0
	for n < len(data) {
		h := sha256.New()
		h.Write([]byte(keyID))
		var buf [4]byte
		binary.BigEndian.PutUint32(buf[:], ctr)
		h.Write(buf[:])
		ks := h.Sum(nil)
		for i := 0; i < len(ks) && n < len(data); i++ {
			out[n] = data[n] ^ ks[i]
			n++
		}
		ctr++
	}
	return out
}
