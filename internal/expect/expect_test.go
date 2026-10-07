package expect

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	sc, err := Parse("# a router\n\nexpect Username:\nsend ${login}\r\nexpect \"Password: \"\nsend ${password}\nexpect >\nsend enable\nsend\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(sc) != 7 || sc[2].Text != "Password: " || !sc[3].Send || sc[6].Text != "" {
		t.Fatalf("parsed = %+v", sc)
	}
	again, err := Parse(sc.String())
	if err != nil || again.String() != sc.String() {
		t.Fatalf("canonical form does not round-trip: %q -> %v", sc.String(), err)
	}
	if !sc.Uses(Password) || Script(DefaultLogin[:2]).Uses(Password) {
		t.Error("Uses is wrong")
	}
	for name, bad := range map[string]string{
		"verb":            "wait 5",
		"empty expect":    "expect",
		"expect password": "expect ${password}",
		"placeholder":     "send ${secret}",
		"open":            "send ${login",
		"long":            "send " + strings.Repeat("x", MaxText+1),
		"quote":           `expect "abc`,
		"steps":           strings.Repeat("send x\n", MaxSteps+1),
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// fakeDevice answers a login dialogue over a pipe: it prints its prompts,
// checks what it is sent, and then prints a banner and a prompt.
func fakeDevice(t *testing.T, conn io.ReadWriter, user, pass string, done chan<- error) {
	t.Helper()
	readLine := func() (string, error) {
		var b []byte
		one := make([]byte, 1)
		for {
			if _, err := conn.Read(one); err != nil {
				return "", err
			}
			if one[0] == '\n' {
				return strings.TrimRight(string(b), "\r"), nil
			}
			b = append(b, one[0])
		}
	}
	go func() {
		_, _ = io.WriteString(conn, "Welcome\r\nlogin: ")
		if l, err := readLine(); err != nil || l != user {
			done <- errors.New("bad user: " + l)
			return
		}
		_, _ = io.WriteString(conn, "Password: ")
		if l, err := readLine(); err != nil || l != pass {
			done <- errors.New("bad password")
			return
		}
		_, _ = io.WriteString(conn, "Last login: never\r\nrouter> ")
		done <- nil
	}()
}

type duplex struct {
	io.Reader
	io.Writer
}

func TestRunDefaultLogin(t *testing.T) {
	devR, toDev := io.Pipe()
	fromDev, devW := io.Pipe()
	done := make(chan error, 1)
	fakeDevice(t, duplex{devR, devW}, "admin", "s3cret!", done)

	s := NewStream(fromDev)
	if err := DefaultLogin.Run(context.Background(), s, toDev, "admin", "s3cret!", "\r\n", 2*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// What the device printed after the password prompt reaches the caller.
	buf := make([]byte, 64)
	var got bytes.Buffer
	for !strings.Contains(got.String(), "router> ") {
		n, err := s.Read(buf)
		if err != nil {
			t.Fatal(err)
		}
		got.Write(buf[:n])
	}
	// The leftover starts right after the matched "assword:": the prompt's
	// trailing space, then everything the device printed after the login.
	if got.String() != " Last login: never\r\nrouter> " {
		t.Fatalf("leftover = %q", got.String())
	}
}

func TestRunTimeoutNamesStepNotSecret(t *testing.T) {
	r, w := io.Pipe()
	defer w.Close()
	s := NewStream(r)
	sc, _ := Parse("send ${password}\nexpect never-printed")
	err := sc.Run(context.Background(), s, io.Discard, "u", "TOPSECRET", "\n", 50*time.Millisecond)
	if !errors.Is(err, ErrTimeout) || !strings.Contains(err.Error(), "step 2") || strings.Contains(err.Error(), "TOPSECRET") {
		t.Fatalf("err = %v", err)
	}
}

func TestRunClosed(t *testing.T) {
	s := NewStream(strings.NewReader("no prompt here"))
	err := DefaultLogin.Run(context.Background(), s, io.Discard, "u", "p", "\n", time.Second)
	if !errors.Is(err, ErrClosed) {
		t.Fatalf("err = %v", err)
	}
}
