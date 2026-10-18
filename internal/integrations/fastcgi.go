package integrations

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"
)

// A minimal FastCGI client: enough to ask PHP-FPM for its status page over
// the pool's own socket, so no web server has to expose it.

const (
	fcgiVersion      = 1
	fcgiBeginRequest = 1
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7
	fcgiResponder    = 1
)

func fcgiRecord(w *bytes.Buffer, typ uint8, content []byte) {
	pad := (8 - len(content)%8) % 8
	h := [8]byte{fcgiVersion, typ, 0, 1, byte(len(content) >> 8), byte(len(content)), byte(pad), 0}
	w.Write(h[:])
	w.Write(content)
	w.Write(make([]byte, pad))
}

func fcgiPair(w *bytes.Buffer, k, v string) {
	for _, n := range []int{len(k), len(v)} {
		if n < 128 {
			w.WriteByte(byte(n))
		} else {
			var b [4]byte
			binary.BigEndian.PutUint32(b[:], uint32(n)|1<<31)
			w.Write(b[:])
		}
	}
	w.WriteString(k)
	w.WriteString(v)
}

// fcgiGet requests path (with query) from the FastCGI server at network/address
// and returns the response body without its CGI headers.
func fcgiGet(ctx context.Context, network, address, path, query string) ([]byte, error) {
	d := net.Dialer{Timeout: 3 * time.Second}
	conn, err := d.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	var req, params bytes.Buffer
	fcgiRecord(&req, fcgiBeginRequest, []byte{0, fcgiResponder, 0, 0, 0, 0, 0, 0})
	for k, v := range map[string]string{
		"SCRIPT_NAME": path, "SCRIPT_FILENAME": path, "REQUEST_URI": path + "?" + query,
		"QUERY_STRING": query, "REQUEST_METHOD": "GET", "SERVER_PROTOCOL": "HTTP/1.1", "GATEWAY_INTERFACE": "CGI/1.1",
	} {
		fcgiPair(&params, k, v)
	}
	fcgiRecord(&req, fcgiParams, params.Bytes())
	fcgiRecord(&req, fcgiParams, nil)
	fcgiRecord(&req, fcgiStdin, nil)
	if _, err := conn.Write(req.Bytes()); err != nil {
		return nil, err
	}

	var stdout bytes.Buffer
	for {
		var h [8]byte
		if _, err := io.ReadFull(conn, h[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(h[4:6])) + int(h[6])
		body := make([]byte, n)
		if _, err := io.ReadFull(conn, body); err != nil {
			return nil, err
		}
		content := body[:binary.BigEndian.Uint16(h[4:6])]
		switch h[1] {
		case fcgiStdout:
			stdout.Write(content)
		case fcgiEndRequest:
			out := stdout.Bytes()
			if i := bytes.Index(out, []byte("\r\n\r\n")); i >= 0 {
				head, rest := out[:i], out[i+4:]
				if bytes.Contains(head, []byte("Status: 404")) || bytes.Contains(head, []byte("Status: 403")) {
					return nil, errors.New("status page not enabled")
				}
				return rest, nil
			}
			return out, nil
		}
	}
}
