package api_test

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/alert"
	"github.com/morandeirachema/pamv1/internal/api"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/icap"
	"github.com/morandeirachema/pamv1/internal/store"
)

// fakeICAP answers RESPMOD: 200 with X-Infection-Found when the body
// carries EICAR, 204 (clean) otherwise.
func fakeICAP(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				r := bufio.NewReader(c)
				var all strings.Builder
				for !strings.HasSuffix(all.String(), "0\r\n\r\n") {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					all.WriteString(line)
				}
				if strings.Contains(all.String(), "EICAR") {
					io.WriteString(c, "ICAP/1.0 200 OK\r\nX-Infection-Found: Type=0; Resolution=2; Threat=Eicar-Test-Signature;\r\nEncapsulated: null-body=0\r\n\r\n")
					return
				}
				io.WriteString(c, "ICAP/1.0 204 No Content\r\nEncapsulated: null-body=0\r\n\r\n")
			}(c)
		}
	}()
	return "icap://" + ln.Addr().String() + "/respmod"
}

type alertBox struct {
	mu sync.Mutex
	ev []alert.Event
}

func (a *alertBox) Notify(_ context.Context, e alert.Event) {
	a.mu.Lock()
	a.ev = append(a.ev, e)
	a.mu.Unlock()
}
func (a *alertBox) count(kind string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	n := 0
	for _, e := range a.ev {
		if e.Type == kind {
			n++
		}
	}
	return n
}

// transferGuacd plays guacd for a desktop with a drive: after the
// handshake it offers two downloads — clean.txt, then eicar.txt — driven by
// the acks it receives, as guacd's download path is; it acks every upload
// instruction it receives, as guacd does; and it reports every instruction
// from the browser side.
func transferGuacd(t *testing.T, got chan<- fakeInst) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		if _, err := readFakeInst(r); err != nil {
			return
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "args", Args: []string{"VERSION_1_5_0", "hostname", "port", "username", "password"}}.Encode()))
		for {
			inst, err := readFakeInst(r)
			if err != nil {
				return
			}
			if inst.op == "connect" {
				break
			}
		}
		conn.Write([]byte(guacd.Instruction{Opcode: "ready", Args: []string{"$xfer"}}.Encode()))
		acks := make(chan string, 64)
		readerDone := make(chan struct{})
		go func() {
			defer close(readerDone)
			for {
				inst, err := readFakeInst(r)
				if err != nil {
					close(acks)
					return
				}
				switch {
				case inst.op == "ack" && len(inst.args) > 0:
					select {
					case acks <- inst.args[0]:
					default: // nobody is waiting on acks any more
					}
				case inst.op == "file" || inst.op == "blob" || inst.op == "end":
					conn.Write([]byte(guacd.Instruction{Opcode: "ack", Args: []string{inst.args[0], "OK (guacd)", "0"}}.Encode()))
				}
				got <- inst
			}
		}()
		waitAck := func(stream string) bool {
			for a := range acks {
				if a == stream {
					return true
				}
			}
			return false
		}
		for _, d := range []struct{ stream, name, body string }{{"7", "clean.txt", "quarterly numbers"}, {"8", "eicar.txt", "X5O!P%@AP EICAR test"}} {
			conn.Write([]byte(guacd.Instruction{Opcode: "file", Args: []string{d.stream, "text/plain", d.name}}.Encode()))
			if !waitAck(d.stream) {
				return
			}
			conn.Write([]byte(guacd.Instruction{Opcode: "blob", Args: []string{d.stream, base64.StdEncoding.EncodeToString([]byte(d.body))}}.Encode()))
			if !waitAck(d.stream) {
				return
			}
			conn.Write([]byte(guacd.Instruction{Opcode: "end", Args: []string{d.stream}}.Encode()))
		}
		// Only the reader goroutine reads r: a second reader here would
		// steal instructions from it.
		<-readerDone
	}()
	return ln.Addr().String()
}

// TestDesktopTransfersScanned proves Phase 280 end to end through the
// portal's viewer tunnel: a clean download and a clean upload cross whole
// after the ICAP service passes them, with guacd's flow control intact and
// its own acks for the upload never reaching the browser twice; an
// infected download never reaches the browser and an infected upload never
// reaches guacd — the browser is told it was refused — and both are
// audited and alerted.
func TestDesktopTransfersScanned(t *testing.T) {
	icapClient, err := icap.NewClient(fakeICAP(t))
	if err != nil {
		t.Fatal(err)
	}
	fromBrowser := make(chan fakeInst, 64)
	box := &alertBox{}
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: transferGuacd(t, fromBrowser), Alerter: box,
		ICAP: icapClient, ICAPDesktop: "all", ICAPDesktopMaxBytes: 1 << 20})
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "Administrator", "secret": "Rdp-S3cret!"})
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/targets/"+itoa(id)+"/rdp?token="+tok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	frames := make(chan string, 256)
	go func() {
		for {
			_, b, err := c.Read(ctx)
			if err != nil {
				close(frames)
				return
			}
			frames <- string(b)
		}
	}()
	var seen []string
	until := func(want string) {
		t.Helper()
		for {
			for _, f := range seen {
				if strings.Contains(f, want) {
					return
				}
			}
			select {
			case f, ok := <-frames:
				if !ok {
					t.Fatalf("tunnel closed before %q; saw %q", want, seen)
				}
				seen = append(seen, f)
				// A browser acks a download's open and each blob.
				if in, ok := guacd.Decode([]byte(f)); ok && (in.Opcode == "file" || in.Opcode == "blob") {
					c.Write(ctx, websocket.MessageText, []byte(guacd.Instruction{Opcode: "ack", Args: []string{in.Args[0], "OK", "0"}}.Encode()))
				}
			case <-ctx.Done():
				t.Fatalf("never saw %q; saw %q", want, seen)
			}
		}
	}
	send := func(op string, args ...string) {
		if err := c.Write(ctx, websocket.MessageText, []byte(guacd.Instruction{Opcode: op, Args: args}.Encode())); err != nil {
			t.Fatal(err)
		}
	}

	// The clean download arrives whole; the infected one never does.
	until("9.clean.txt")
	until(guacd.Instruction{Opcode: "end", Args: []string{"7"}}.Encode())
	auditHasEventually(t, st, "rdp.transfer_blocked", "eicar.txt")
	for _, f := range seen {
		if strings.Contains(f, "eicar.txt") || strings.Contains(f, base64.StdEncoding.EncodeToString([]byte("X5O!P%@AP EICAR test"))) {
			t.Fatalf("the infected download reached the browser: %q", f)
		}
	}

	// A clean upload: acked by the gate as it goes, released whole.
	send("file", "3", "text/plain", "up.txt")
	until("3.ack,1.3,2.OK")
	send("blob", "3", base64.StdEncoding.EncodeToString([]byte("meeting notes")))
	send("end", "3")
	auditHasEventually(t, st, "rdp.transfer_scanned", "up.txt")
	// An infected upload: refused back to the browser, never sent to guacd.
	send("file", "4", "text/plain", "bad.txt")
	send("blob", "4", base64.StdEncoding.EncodeToString([]byte("EICAR")))
	send("end", "4")
	until("Blocked by content scan")

	deadline := time.After(5 * time.Second)
	var toGuacd []string
	for len(toGuacd) < 3 {
		select {
		case in := <-fromBrowser:
			if len(in.args) > 0 && (in.args[0] == "3" || in.args[0] == "4") {
				toGuacd = append(toGuacd, in.op+":"+in.args[0])
			}
		case <-deadline:
			t.Fatalf("guacd received only %v of the clean upload", toGuacd)
		}
	}
	if strings.Join(toGuacd, " ") != "file:3 blob:3 end:3" {
		t.Fatalf("guacd received %v, want the clean upload whole and nothing of the infected one", toGuacd)
	}
	auditHasEventually(t, st, "rdp.transfer_blocked", "bad.txt")
	auditHas(t, st, "rdp.transfer_scanned", "clean.txt")
	auditHas(t, st, "rdp.transfer_blocked", "outcome:infected")
	// The alert follows the audit row on the tunnel's goroutine.
	for wait := time.Now().Add(5 * time.Second); box.count("rdp.transfer_blocked") < 2 && time.Now().Before(wait); {
		time.Sleep(10 * time.Millisecond)
	}
	if n := box.count("rdp.transfer_blocked"); n != 2 {
		t.Fatalf("blocked transfers alerted %d times, want 2", n)
	}
	// guacd acked the upload's open, blob and end; the gate had already
	// answered the first two, so only guacd's END ack reaches the browser —
	// its own verdict on the write (review of 274-280).
	until("10.OK (guacd)")
	n, fromGuacd := 0, 0
	for _, f := range seen {
		if strings.HasPrefix(f, "3.ack,1.3,") {
			n++
			if strings.Contains(f, "OK (guacd)") {
				fromGuacd++
			}
		}
	}
	if n != 3 || fromGuacd != 1 {
		t.Fatalf("stream 3 acks seen by the browser: %d, %d of them guacd's; want 3 and 1", n, fromGuacd)
	}
}

// auditHasEventually waits for an audit row written by the tunnel's own
// goroutines.
func auditHasEventually(t *testing.T, st store.Store, action, want string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		events, err := st.ListAudit(context.Background(), 500)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if e.Action == action && strings.Contains(e.Detail, want) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no audit event action=%q containing %q", action, want)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestDesktopGateClosesOnUnframeable (review of 274-280): with scanning on,
// a message the gate cannot frame ends the tunnel, audited, and none of it
// reaches guacd.
func TestDesktopGateClosesOnUnframeable(t *testing.T) {
	icapClient, err := icap.NewClient(fakeICAP(t))
	if err != nil {
		t.Fatal(err)
	}
	fromBrowser := make(chan fakeInst, 64)
	srv, st := newTestServerOpts(t, nil, api.Options{GuacdAddr: transferGuacd(t, fromBrowser),
		ICAP: icapClient, ICAPDesktop: "all", ICAPDesktopMaxBytes: 1 << 20})
	_, data := do(t, srv, "POST", "/api/targets", testAPIKey, map[string]any{"name": "win-rdp", "host": "10.0.0.9", "port": 3389, "os_type": "windows", "protocol": "rdp"})
	id := int64(jsonMap(t, data)["id"].(float64))
	do(t, srv, "POST", "/api/credentials", testAPIKey, map[string]any{"target_id": id, "username": "Administrator", "secret": "Rdp-S3cret!"})
	_, data = do(t, srv, "POST", "/api/rdp-token", testAPIKey, nil)
	tok := jsonMap(t, data)["token"].(string)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/api/targets/"+itoa(id)+"/rdp?token="+tok, &websocket.DialOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")
	msg := "0003.nop;" + guacd.Instruction{Opcode: "file", Args: []string{"1", "text/plain", "x"}}.Encode()
	if err := c.Write(ctx, websocket.MessageText, []byte(msg)); err != nil {
		t.Fatal(err)
	}
	auditHasEventually(t, st, "rdp.refused", "reason:unframeable-instruction direction:in")
	for {
		if _, _, err := c.Read(ctx); err != nil {
			break // the tunnel closed
		}
	}
	select {
	case in := <-fromBrowser:
		if in.op == "file" {
			t.Fatal("the unframeable message's file stream reached guacd")
		}
	default:
	}
}
