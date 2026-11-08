package probe

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
)

// StartTLSPorts lists the supported STARTTLS protocols and the port used
// when a request names a protocol but no port.
var StartTLSPorts = map[string]int{
	"smtp":     25,
	"imap":     143,
	"pop3":     110,
	"ftp":      21,
	"ldap":     389,
	"postgres": 5432,
}

// AutoStartTLS maps the ports where servers normally expect STARTTLS rather
// than TLS from the first byte. A request on one of these ports uses that
// protocol unless it asks otherwise ("none" forces plain TLS).
var AutoStartTLS = map[int]string{
	21:   "ftp",
	25:   "smtp",
	110:  "pop3",
	143:  "imap",
	389:  "ldap",
	587:  "smtp",
	5432: "postgres",
}

// StartTLSNames returns the supported protocol names, sorted.
func StartTLSNames() []string {
	out := make([]string, 0, len(StartTLSPorts))
	for k := range StartTLSPorts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// Limits on what a server may send before the upgrade, so a hostile or
// chatty server cannot make the probe read without end.
const (
	maxLineLen = 4096
	maxLines   = 100
)

// startTLS runs the plain-text exchange that asks the server to switch the
// connection to TLS. The caller sets a deadline on conn. On success the next
// bytes on conn are the server's side of the TLS handshake.
func startTLS(conn net.Conn, proto string) error {
	r := bufio.NewReaderSize(conn, maxLineLen)
	switch proto {
	case "smtp":
		if _, err := replyCode(r, "220"); err != nil {
			return fmt.Errorf("SMTP greeting: %w", err)
		}
		if err := send(conn, "EHLO ca-chain-check.invalid\r\n"); err != nil {
			return err
		}
		if _, err := replyCode(r, "250"); err != nil {
			return fmt.Errorf("SMTP EHLO: %w", err)
		}
		if err := send(conn, "STARTTLS\r\n"); err != nil {
			return err
		}
		if _, err := replyCode(r, "220"); err != nil {
			return fmt.Errorf("SMTP STARTTLS: %w", err)
		}
	case "ftp":
		if _, err := replyCode(r, "220"); err != nil {
			return fmt.Errorf("FTP greeting: %w", err)
		}
		if err := send(conn, "AUTH TLS\r\n"); err != nil {
			return err
		}
		if _, err := replyCode(r, "234"); err != nil {
			return fmt.Errorf("FTP AUTH TLS: %w", err)
		}
	case "imap":
		line, err := readLine(r)
		if err != nil {
			return fmt.Errorf("IMAP greeting: %w", err)
		}
		if !strings.HasPrefix(line, "* OK") {
			return fmt.Errorf("IMAP greeting: unexpected reply %q", clip(line))
		}
		if err := send(conn, "a1 STARTTLS\r\n"); err != nil {
			return err
		}
		for i := 0; ; i++ {
			if i >= maxLines {
				return errors.New("IMAP STARTTLS: too many lines before the reply")
			}
			line, err := readLine(r)
			if err != nil {
				return fmt.Errorf("IMAP STARTTLS: %w", err)
			}
			if strings.HasPrefix(line, "a1 ") {
				if !strings.HasPrefix(line, "a1 OK") {
					return fmt.Errorf("IMAP STARTTLS refused: %q", clip(line))
				}
				break
			}
		}
	case "pop3":
		line, err := readLine(r)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("POP3 greeting: %s", replyErr(line, err))
		}
		if err := send(conn, "STLS\r\n"); err != nil {
			return err
		}
		line, err = readLine(r)
		if err != nil || !strings.HasPrefix(line, "+OK") {
			return fmt.Errorf("POP3 STLS refused: %s", replyErr(line, err))
		}
	case "postgres":
		// SSLRequest: length 8, then the magic code 80877103.
		var msg [8]byte
		binary.BigEndian.PutUint32(msg[0:], 8)
		binary.BigEndian.PutUint32(msg[4:], 80877103)
		if _, err := conn.Write(msg[:]); err != nil {
			return err
		}
		b, err := r.ReadByte()
		if err != nil {
			return fmt.Errorf("PostgreSQL SSLRequest: %w", err)
		}
		if b != 'S' {
			return fmt.Errorf("PostgreSQL refused TLS (replied %q)", b)
		}
	case "ldap":
		if err := ldapStartTLS(conn, r); err != nil {
			return fmt.Errorf("LDAP StartTLS: %w", err)
		}
	default:
		return fmt.Errorf("unsupported STARTTLS protocol %q", proto)
	}
	// Anything the server sent after its go-ahead would be read as TLS
	// bytes we have already consumed; treat it as a protocol error.
	if r.Buffered() > 0 {
		return errors.New("server sent data after agreeing to start TLS")
	}
	return nil
}

func send(conn net.Conn, s string) error {
	_, err := io.WriteString(conn, s)
	return err
}

// readLine reads one CRLF- or LF-terminated line, without the terminator.
func readLine(r *bufio.Reader) (string, error) {
	line, isPrefix, err := r.ReadLine()
	if err != nil {
		return "", err
	}
	if isPrefix {
		return "", errors.New("reply line too long")
	}
	return string(line), nil
}

// replyCode reads an SMTP/FTP style reply ("250-..." continuation lines,
// then "250 ...") and checks its three-digit code.
func replyCode(r *bufio.Reader, want string) (string, error) {
	for i := 0; i < maxLines; i++ {
		line, err := readLine(r)
		if err != nil {
			return "", err
		}
		if len(line) < 3 {
			return "", fmt.Errorf("unexpected reply %q", clip(line))
		}
		if len(line) > 3 && line[3] == '-' {
			continue
		}
		if line[:3] != want {
			return "", fmt.Errorf("server replied %q", clip(line))
		}
		return line, nil
	}
	return "", errors.New("too many reply lines")
}

func replyErr(line string, err error) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf("server replied %q", clip(line))
}

func clip(s string) string {
	if len(s) > 120 {
		return s[:120] + "…"
	}
	return s
}

// ldapStartTLSRequest is an LDAPMessage with messageID 1 and an
// ExtendedRequest for OID 1.3.6.1.4.1.1466.20037 (RFC 4511 section 4.14).
var ldapStartTLSRequest = append([]byte{0x30, 0x1d, 0x02, 0x01, 0x01, 0x77, 0x18, 0x80, 0x16},
	"1.3.6.1.4.1.1466.20037"...)

func ldapStartTLS(conn net.Conn, r *bufio.Reader) error {
	if _, err := conn.Write(ldapStartTLSRequest); err != nil {
		return err
	}
	tag, body, err := berRead(r)
	if err != nil {
		return err
	}
	if tag != 0x30 {
		return fmt.Errorf("unexpected reply (tag %#x)", tag)
	}
	// messageID INTEGER, then ExtendedResponse [APPLICATION 24].
	rest, err := berSkip(body, 0x02)
	if err != nil {
		return err
	}
	if len(rest) < 2 || rest[0] != 0x78 {
		return errors.New("reply is not an extended response")
	}
	resp, _, err := berSplit(rest)
	if err != nil {
		return err
	}
	// resultCode ENUMERATED is first; 0 means success.
	if len(resp) < 3 || resp[0] != 0x0a || resp[1] != 0x01 {
		return errors.New("reply has no result code")
	}
	if resp[2] != 0 {
		return fmt.Errorf("server refused (result code %d)", resp[2])
	}
	return nil
}

// berRead reads one BER element (tag, definite length, value) from r.
func berRead(r *bufio.Reader) (byte, []byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return 0, nil, err
	}
	n, err := berLen(r)
	if err != nil {
		return 0, nil, err
	}
	if n > 64*1024 {
		return 0, nil, errors.New("reply too large")
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return 0, nil, err
	}
	return tag, buf, nil
}

func berLen(r io.ByteReader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	if b < 0x80 {
		return int(b), nil
	}
	k := int(b & 0x7f)
	if k == 0 || k > 3 {
		return 0, errors.New("unsupported BER length")
	}
	n := 0
	for i := 0; i < k; i++ {
		c, err := r.ReadByte()
		if err != nil {
			return 0, err
		}
		n = n<<8 | int(c)
	}
	return n, nil
}

// berSplit returns the value of the element at the start of b and what
// follows it.
func berSplit(b []byte) (value, rest []byte, err error) {
	br := &sliceReader{b: b[1:]}
	n, err := berLen(br)
	if err != nil {
		return nil, nil, err
	}
	if n > len(br.b) {
		return nil, nil, errors.New("truncated reply")
	}
	return br.b[:n], br.b[n:], nil
}

// berSkip checks that b starts with an element of the given tag and returns
// what follows it.
func berSkip(b []byte, tag byte) ([]byte, error) {
	if len(b) == 0 || b[0] != tag {
		return nil, errors.New("malformed reply")
	}
	_, rest, err := berSplit(b)
	return rest, err
}

type sliceReader struct{ b []byte }

func (s *sliceReader) ReadByte() (byte, error) {
	if len(s.b) == 0 {
		return 0, io.ErrUnexpectedEOF
	}
	c := s.b[0]
	s.b = s.b[1:]
	return c, nil
}
