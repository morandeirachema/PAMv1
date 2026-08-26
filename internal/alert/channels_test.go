package alert

import (
	"context"
	"encoding/base64"
	"net"
	"net/smtp"
	"strings"
	"testing"
	"time"
)

// TestSyslogNotify sends an alert to an in-process UDP listener and checks the
// RFC 5424 line carries the event.
func TestSyslogNotify(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()

	s := NewSyslog("udp", pc.LocalAddr().String(), "PAMv1")
	s.Notify(context.Background(), Event{Type: "breakglass.access", Actor: "alice", Detail: "x", Time: time.Now()})

	buf := make([]byte, 2048)
	_ = pc.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := pc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("no syslog datagram: %v", err)
	}
	got := string(buf[:n])
	if !strings.HasPrefix(got, "<81>1 ") {
		t.Fatalf("bad syslog prefix: %q", got)
	}
	if !strings.Contains(got, "breakglass.access") || !strings.Contains(got, "actor=alice") {
		t.Fatalf("syslog line missing event: %q", got)
	}
}

// TestEmailNotify checks the SMTP message is formed with the subject, body and
// recipients (send is stubbed — no real SMTP server).
func TestEmailNotify(t *testing.T) {
	gotMsg := make(chan []byte, 1)
	var gotTo []string
	e := &Email{
		addr: "smtp.internal:25", from: "pam@example.com", to: []string{"a@x", "b@x"},
		send: func(_ string, _ smtp.Auth, _ string, to []string, msg []byte) error {
			gotTo = to
			gotMsg <- msg
			return nil
		},
	}
	e.Notify(context.Background(), Event{Type: "breakglass.unseal", Actor: "bob"})

	select {
	case msg := <-gotMsg:
		s := string(msg)
		if !strings.Contains(s, "Subject: [PAMv1] breakglass.unseal by bob") || !strings.Contains(s, "Type: breakglass.unseal") {
			t.Fatalf("email body missing fields: %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("email was not sent")
	}
	if len(gotTo) != 2 {
		t.Fatalf("recipients = %v", gotTo)
	}
}

// deadlineConn is a net.Conn stub that records the write deadline it was given
// and accepts any write; only the methods Syslog.Notify calls are implemented.
type deadlineConn struct {
	net.Conn
	gotDeadline chan time.Time
}

func (c *deadlineConn) SetWriteDeadline(t time.Time) error { c.gotDeadline <- t; return nil }
func (c *deadlineConn) Write(p []byte) (int, error)        { return len(p), nil }
func (c *deadlineConn) Close() error                       { return nil }

// TestSyslogWriteIsBounded proves Notify arms a write deadline before writing, so
// a connected-but-stalled TCP syslog sink cannot park the delivery goroutine.
func TestSyslogWriteIsBounded(t *testing.T) {
	dc := &deadlineConn{gotDeadline: make(chan time.Time, 1)}
	s := NewSyslog("tcp", "203.0.113.1:514", "PAMv1") // TEST-NET-3: never actually dialed
	s.dial = func(_, _ string) (net.Conn, error) { return dc, nil }
	s.Notify(context.Background(), Event{Type: "breakglass.access", Actor: "a"})
	select {
	case dl := <-dc.gotDeadline:
		if dl.IsZero() {
			t.Fatal("syslog write deadline is zero — the write is unbounded")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("syslog Notify never set a write deadline")
	}
}

// captureNotifier records events for the Multi test.
type captureNotifier struct{ ch chan Event }

// Notify records e.
func (c captureNotifier) Notify(_ context.Context, e Event) { c.ch <- e }

// TestMultiFansOut checks Multi delivers to every notifier.
func TestMultiFansOut(t *testing.T) {
	a := captureNotifier{make(chan Event, 1)}
	b := captureNotifier{make(chan Event, 1)}
	Multi{a, b}.Notify(context.Background(), Event{Type: "x"})
	for _, c := range []captureNotifier{a, b} {
		select {
		case <-c.ch:
		case <-time.After(time.Second):
			t.Fatal("Multi did not deliver to a notifier")
		}
	}
}

// TestBuildDirectMessagePlain proves a text-only (no inline image) message
// carries the To/Subject/From headers and the HTML body verbatim, and that a
// crafted recipient/subject cannot inject extra headers via CR/LF.
func TestBuildDirectMessagePlain(t *testing.T) {
	msg, err := buildDirectMessage("pam@example.com", "carol@example.com\r\nBcc: evil@example.com",
		"you're invited\r\nX-Injected: yes", "<p>hello</p>", nil, "")
	if err != nil {
		t.Fatalf("buildDirectMessage: %v", err)
	}
	s := string(msg)
	// auditfmt.OneLine replaces CR/LF with spaces rather than deleting them, so
	// the injected text can still appear as inert content INSIDE the To:/
	// Subject: header's own value — the property that actually matters is
	// that it never starts a new header line (no literal \r\n before it).
	if strings.Contains(s, "\r\nBcc:") || strings.Contains(s, "\r\nX-Injected:") {
		t.Fatalf("CR/LF in To/Subject was not stripped, header injection possible: %q", s)
	}
	if !strings.Contains(s, "From: pam@example.com") {
		t.Fatalf("missing From header: %q", s)
	}
	if !strings.Contains(s, "Content-Type: text/html; charset=utf-8") || !strings.Contains(s, "<p>hello</p>") {
		t.Fatalf("missing HTML body: %q", s)
	}
	if strings.Contains(s, "image/png") {
		t.Fatalf("no image was requested but the message has an image part: %q", s)
	}
}

// TestBuildDirectMessageInlineImage proves an inline PNG is attached as a
// base64 image/png part with a matching Content-ID the HTML body can
// reference via cid:.
func TestBuildDirectMessageInlineImage(t *testing.T) {
	png := []byte{0x89, 'P', 'N', 'G', 0, 1, 2, 3}
	msg, err := buildDirectMessage("pam@example.com", "carol@example.com", "subj",
		`<img src="cid:qr">`, png, "qr")
	if err != nil {
		t.Fatalf("buildDirectMessage: %v", err)
	}
	s := string(msg)
	if !strings.Contains(s, "Content-Type: multipart/related") {
		t.Fatalf("expected a multipart/related message: %q", s)
	}
	if !strings.Contains(s, "Content-ID: <qr>") || !strings.Contains(s, "Content-Type: image/png") {
		t.Fatalf("missing inline image part: %q", s)
	}
	wantB64 := base64.StdEncoding.EncodeToString(png)
	if !strings.Contains(s, wantB64) {
		t.Fatalf("base64 PNG payload not found in message: %q", s)
	}
}

// fakeSMTP starts a minimal, single-connection SMTP server (no STARTTLS/AUTH
// extensions offered, so SendMailBounded's client skips both branches) that
// captures the DATA payload it receives, for an end-to-end SendDirect test
// with no real mail relay.
func fakeSMTP(t *testing.T) (addr string, got chan []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	got = make(chan []byte, 1)
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reply := func(s string) { conn.Write([]byte(s + "\r\n")) }
		reply("220 fake.smtp ready")
		buf := make([]byte, 65536)
		var data strings.Builder
		inData := false
		for {
			n, err := conn.Read(buf)
			if err != nil {
				return
			}
			chunk := string(buf[:n])
			if inData {
				data.WriteString(chunk)
				if strings.HasSuffix(data.String(), "\r\n.\r\n") {
					got <- []byte(strings.TrimSuffix(data.String(), "\r\n.\r\n"))
					reply("250 OK")
					inData = false
				}
				continue
			}
			for _, line := range strings.Split(strings.TrimRight(chunk, "\r\n"), "\r\n") {
				up := strings.ToUpper(line)
				switch {
				case strings.HasPrefix(up, "EHLO"), strings.HasPrefix(up, "HELO"):
					reply("250 fake.smtp")
				case strings.HasPrefix(up, "MAIL FROM"):
					reply("250 OK")
				case strings.HasPrefix(up, "RCPT TO"):
					reply("250 OK")
				case strings.HasPrefix(up, "DATA"):
					reply("354 go ahead")
					inData = true
					data.Reset()
				case strings.HasPrefix(up, "QUIT"):
					reply("221 bye")
					return
				}
			}
		}
	}()
	return ln.Addr().String(), got
}

// TestSendDirectEndToEnd proves SendDirect actually delivers a well-formed
// message over the wire (no field injection here — a real, if minimal, SMTP
// listener) — the one test in this file that exercises SendMailBounded
// against a real connection rather than a stubbed send func.
func TestSendDirectEndToEnd(t *testing.T) {
	addr, got := fakeSMTP(t)
	png := []byte{0x89, 'P', 'N', 'G'}
	if err := SendDirect(addr, "pam@example.com", "carol@example.com", "", "",
		"You're invited", `<img src="cid:qr">`, png, "qr"); err != nil {
		t.Fatalf("SendDirect: %v", err)
	}
	select {
	case msg := <-got:
		s := string(msg)
		if !strings.Contains(s, "Subject: You're invited") {
			t.Fatalf("subject missing: %q", s)
		}
		if !strings.Contains(s, "Content-ID: <qr>") {
			t.Fatalf("inline image missing: %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fake SMTP server never received a DATA payload")
	}
}
