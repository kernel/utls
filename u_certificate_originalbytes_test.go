package tls

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
)

// buildTLS13CertificateWithLeafExtension builds a valid TLS 1.3 Certificate
// handshake message whose leaf certificate carries an extension that
// marshalCertificate does not re-emit (it only re-emits OCSP and SCT).
// Re-marshaling therefore drops the extension, so a transcript computed from
// the re-marshal diverges from the peer's — which makes CertificateVerify fail
// with "crypto/rsa: verification error".
func buildTLS13CertificateWithLeafExtension() []byte {
	var b cryptobyte.Builder
	b.AddUint8(typeCertificate)
	b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddUint8(0) // empty certificate_request_context
		b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
			// single leaf certificate
			b.AddUint24LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddBytes([]byte("dummy-leaf-der"))
			})
			// leaf extensions: one extension that unmarshal ignores and
			// marshalCertificate never re-emits.
			b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
				b.AddUint16(0x1234) // unknown extension type
				b.AddUint16LengthPrefixed(func(b *cryptobyte.Builder) {
					b.AddBytes([]byte("ext-payload"))
				})
			})
		})
	})
	out, err := b.Bytes()
	if err != nil {
		panic(err)
	}
	return out
}

// TestCertificateMsgTLS13PreservesOriginalBytes ensures certificateMsgTLS13
// feeds transcriptMsg the exact bytes it was unmarshaled from, not a
// (potentially lossy) re-marshal.
func TestCertificateMsgTLS13PreservesOriginalBytes(t *testing.T) {
	wire := buildTLS13CertificateWithLeafExtension()

	var m certificateMsgTLS13
	if !m.unmarshal(wire) {
		t.Fatal("unmarshal failed")
	}

	wm, ok := handshakeMessage(&m).(handshakeMessageWithOriginalBytes)
	if !ok {
		t.Fatal("certificateMsgTLS13 does not implement handshakeMessageWithOriginalBytes")
	}
	if !bytes.Equal(wm.originalBytes(), wire) {
		t.Fatalf("originalBytes() != wire\n orig=%x\n wire=%x", wm.originalBytes(), wire)
	}

	// Guard: the re-marshal must actually diverge from the wire, otherwise the
	// test is no longer exercising the bug.
	remarshaled, err := m.marshal()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Equal(remarshaled, wire) {
		t.Fatal("re-marshal unexpectedly equals wire; test no longer exercises the divergence")
	}

	// transcriptMsg must hash the original wire bytes, not the re-marshal.
	h := sha256.New()
	if err := transcriptMsg(&m, h); err != nil {
		t.Fatalf("transcriptMsg: %v", err)
	}
	want := sha256.Sum256(wire)
	if got := h.Sum(nil); !bytes.Equal(got, want[:]) {
		t.Fatal("transcriptMsg hashed the re-marshal instead of the original wire bytes")
	}
}

func TestCertificateVerifyWithUnknownCertificateEntryExtension(t *testing.T) {
	// The recorded server flight contains an unknown extension on the leaf
	// CertificateEntry and a CertificateVerify signature over those exact bytes.
	fixture, err := os.Open("testdata/Client-TLSv13-CertificateEntryUnknownExtension")
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()

	flows, err := parseTestData(fixture)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	root, err := x509.ParseCertificate(testRSACertificateIssuer)
	if err != nil {
		t.Fatalf("parse root certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(root)

	config := testConfig.Clone()
	config.MinVersion = VersionTLS13
	config.MaxVersion = VersionTLS13
	config.InsecureSkipVerify = false
	config.RootCAs = roots
	config.ServerName = "example.golang"
	config.Time = func() time.Time { return time.Unix(1_600_000_000, 0) }

	client := UClient(&replayingConn{t: t, flows: flows}, config, HelloGolang)
	if err := client.Handshake(); err != nil {
		t.Fatalf("handshake: %v", err)
	}
	if state := client.ConnectionState(); state.Version != VersionTLS13 {
		t.Fatalf("negotiated TLS version %x, want %x", state.Version, VersionTLS13)
	}
	if _, err := client.Write([]byte("hello\n")); err != nil {
		t.Fatalf("write application data: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}
