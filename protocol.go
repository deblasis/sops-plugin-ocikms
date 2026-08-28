package ocikms

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// The sops-plugin/1 wire protocol: one JSON object per LF-terminated line,
// lockstep request/response over the plugin's stdin/stdout. Types below
// restate the contract from the spec (docs/plugins/spec.md in the sops repo)
// the way any third-party author would; nothing is imported from sops.

const (
	protocolName    = "sops-plugin"
	protocolVersion = 1
	// PluginName is the handshake name; the wrapped-blob prefix must use the
	// BINARY name (sops-plugin-<name>), which is the same string here.
	PluginName = "ocikms"
	// BlobPrefix versions the wrapped key so a foreign or corrupt blob is
	// distinguishable from a backend failure.
	BlobPrefix = "ocikms.v1."
	// maxLineSize mirrors the host's 1 MiB cap; requests that big are already
	// a protocol violation, so reject instead of buffering them whole.
	maxLineSize = 1 << 20
)

// Frozen v1 error codes. ok:false is an answer, never a crash.
const (
	CodeInvalidRequest    = "invalid_request"
	CodeUnsupportedAction = "unsupported_action"
	CodeConfigError       = "config_error"
	CodeAuthFailed        = "auth_failed"
	CodeKeyUnavailable    = "key_unavailable"
	CodeInternal          = "internal"
)

// WireError is a handled failure carrying one of the frozen codes.
type WireError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *WireError) Error() string { return e.Code + ": " + e.Message }

// asWireError keeps unknown handler failures inside the taxonomy.
func asWireError(err error) *WireError {
	var we *WireError
	if errors.As(err, &we) {
		return we
	}
	return &WireError{Code: CodeInternal, Message: err.Error()}
}

type handshakeIn struct {
	Protocol   string `json:"protocol"`
	MaxVersion int    `json:"max_version"`
}

type handshakeOut struct {
	Protocol      string `json:"protocol"`
	Version       int    `json:"version"`
	Plugin        string `json:"plugin"`
	PluginVersion string `json:"plugin_version"`
}

type request struct {
	ID        int64          `json:"id"`
	Action    string         `json:"action"`
	Config    map[string]any `json:"config"`
	Plaintext []byte         `json:"plaintext"` // base64 on the wire
	Wrapped   string         `json:"wrapped"`
}

type response struct {
	ID        int64      `json:"id"`
	OK        bool       `json:"ok"`
	Plaintext []byte     `json:"plaintext,omitempty"` // base64 on the wire
	Wrapped   string     `json:"wrapped,omitempty"`
	KeyRef    string     `json:"key_ref,omitempty"`
	Error     *WireError `json:"error,omitempty"`
}

// Handler is what the protocol loop drives: wrap and unwrap a data key.
// Errors are returned as *WireError so failures stay answers, not crashes.
type Handler interface {
	Encrypt(config map[string]any, plaintext []byte) (wrapped, keyRef string, err error)
	Decrypt(wrapped string) (plaintext []byte, err error)
}

// Serve runs the protocol: handshake, then one response per request line,
// until stdin closes (clean exit). A returned error means the stream itself
// was unusable; the caller should exit non-zero.
func Serve(in io.Reader, out io.Writer, h Handler, pluginVersion string) error {
	// sized so a max-length line plus terminator fits one ReadSlice
	r := bufio.NewReaderSize(in, maxLineSize+1)
	w := bufio.NewWriter(out)

	line, err := readLine(r)
	if err != nil {
		return fmt.Errorf("reading handshake: %w", err)
	}
	var hs handshakeIn
	if err := json.Unmarshal(line, &hs); err != nil {
		return fmt.Errorf("handshake line is not valid JSON")
	}
	if hs.Protocol != protocolName {
		return fmt.Errorf("handshake protocol %q is not %q", hs.Protocol, protocolName)
	}
	if hs.MaxVersion < protocolVersion {
		return fmt.Errorf("host max_version %d is older than protocol version %d", hs.MaxVersion, protocolVersion)
	}
	writeLine(w, handshakeOut{
		Protocol:      protocolName,
		Version:       protocolVersion,
		Plugin:        PluginName,
		PluginVersion: pluginVersion,
	})

	for {
		line, err := readLine(r)
		if errors.Is(err, io.EOF) {
			return nil // stdin closed: normal end of session
		}
		if err != nil {
			return err
		}
		writeLine(w, dispatch(h, line))
	}
}

func dispatch(h Handler, line []byte) response {
	var req request
	if err := json.Unmarshal(line, &req); err != nil || req.Action == "" {
		// an unparseable request has no trustworthy id to echo
		return response{ID: 0, OK: false, Error: &WireError{
			Code:    CodeInvalidRequest,
			Message: "request is not a valid sops-plugin/1 JSON object",
		}}
	}
	switch req.Action {
	case "encrypt":
		wrapped, keyRef, err := h.Encrypt(req.Config, req.Plaintext)
		if err != nil {
			return response{ID: req.ID, OK: false, Error: asWireError(err)}
		}
		if wrapped == "" {
			return response{ID: req.ID, OK: false, Error: &WireError{
				Code:    CodeInternal,
				Message: "handler produced an empty wrapped value",
			}}
		}
		return response{ID: req.ID, OK: true, Wrapped: wrapped, KeyRef: keyRef}
	case "decrypt":
		plaintext, err := h.Decrypt(req.Wrapped)
		if err != nil {
			return response{ID: req.ID, OK: false, Error: asWireError(err)}
		}
		if len(plaintext) == 0 {
			return response{ID: req.ID, OK: false, Error: &WireError{
				Code:    CodeInternal,
				Message: "handler produced an empty plaintext",
			}}
		}
		return response{ID: req.ID, OK: true, Plaintext: plaintext}
	default:
		return response{ID: req.ID, OK: false, Error: &WireError{
			Code:    CodeUnsupportedAction,
			Message: "action " + strconv.Quote(req.Action) + " is not implemented",
		}}
	}
}

// readLine returns one line without its LF. Inbound CRLF is accepted
// leniently: a trailing CR is valid JSON whitespace, so json.Unmarshal
// downstream tolerates it. The spec's CR prohibition governs what the
// plugin EMITS (see writeLine); this plugin never writes CR. Trailing bytes
// without a terminator mean the host died mid-write: treated as end of
// stream, never as a complete request.
func readLine(r *bufio.Reader) ([]byte, error) {
	line, err := r.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		return nil, fmt.Errorf("line exceeds the %d byte cap", maxLineSize)
	}
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, io.EOF
		}
		return nil, err
	}
	return line[:len(line)-1], nil
}

func writeLine(w *bufio.Writer, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		// only reachable with unmarshalable handler values; never on the
		// fixed-shape handshake responses
		b = []byte(fmt.Sprintf(`{"id":0,"ok":false,"error":{"code":"internal","message":%q}}`, err.Error()))
	}
	w.Write(b)
	w.WriteByte('\n')
	// the spec's hang bug: every response is flushed before reading on
	w.Flush()
}
