package api

// graphical_watch.go gives a graphical session (RDP/VNC through guacd) the two
// things a text session has had since Phases 16 and 26 (Phase 258):
//
//   - a RECORDING the portal writes itself — the Guacamole instruction stream
//     guacd sends the operator's browser, which is exactly the format guacd's
//     own recordings use and Guacamole.SessionRecording replays. It lands in
//     the same recording directory as every other recording, sealed at rest
//     when that is on, its SHA-256 audited (rdp.record / vnc.record), so it
//     lists, replays and hash-checks like an asciicast. guacd's own
//     server-side recording (PAM_GUACD_RECORDING_PATH) is unchanged; it lives
//     on guacd's filesystem, which the portal never reads.
//
//   - LIVE WATCHING, by joining the operator's guacd connection as a second,
//     read-only user. guacd sends a joining user the current display before
//     any update, so a supervisor who arrives mid-session sees the desktop,
//     not a black screen that fills in as regions repaint. Read-only is
//     enforced twice: guacd's per-user "read-only" argument (a guacd that does
//     not advertise it is refused, not trusted), and this bridge, which
//     forwards nothing from the watcher's browser but protocol keep-alive.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/coder/websocket"

	"github.com/morandeirachema/pamv1/internal/auth"
	"github.com/morandeirachema/pamv1/internal/guacd"
	"github.com/morandeirachema/pamv1/internal/recording"
)

// errViewerRecordingLimit ends a graphical session whose recording reached
// PAM_MAX_RECORDING_MB — the same rule the SSH proxy applies: a session is not
// allowed to continue unrecorded because it was busy.
var errViewerRecordingLimit = errors.New("api: graphical session recording size limit reached")

// watchTokenTTL bounds a watch token: long enough to open a WebSocket, short
// enough that a copy lifted from a URL is already dead.
const watchTokenTTL = 60 * time.Second

// viewerJoin is what a watcher needs to join a live graphical session: guacd's
// id for the operator's connection, and a channel closed when that session
// ends, so a watcher is released even by a guacd that keeps it open.
type viewerJoin struct {
	conn     string
	protocol string
	target   string
	actor    string
	done     <-chan struct{}
}

// viewerRecording writes one graphical session's instruction stream to disk,
// hashing the STORED bytes (sealed or not) — what playback re-hashes.
type viewerRecording struct {
	mu     sync.Mutex
	f      *os.File
	path   string
	w      io.Writer // the sealer, or the hashed file itself
	hasher hash.Hash
	stored int64 // bytes on disk
	raw    int64 // instruction bytes recorded, for the cap
	max    int64 // 0 = unlimited
	closed bool
}

// countingWriter counts what passes through to the file and the hasher.
type countingWriter struct {
	w io.Writer
	n *int64
}

func (c countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	*c.n += int64(n)
	return n, err
}

// openViewerRecording creates the recording for a graphical session, or
// returns (nil, nil) when no recording directory is configured.
func (s *Server) openViewerRecording(ctx context.Context, target, actor string) (*viewerRecording, error) {
	if s.recordingDir == "" {
		return nil, nil
	}
	if err := os.MkdirAll(s.recordingDir, 0o700); err != nil {
		return nil, err
	}
	name := recording.Title(s.opaqueRecNames, time.Now(), sanitizeName(target), sanitizeName(actor)) + ".guac"
	path := filepath.Join(s.recordingDir, name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) // #nosec G304 -- name is built from sanitized parts under the recording dir
	if err != nil {
		return nil, err
	}
	rec := &viewerRecording{f: f, path: path, hasher: sha256.New(), max: s.maxRecordingBytes}
	sink := countingWriter{w: io.MultiWriter(f, rec.hasher), n: &rec.stored}
	rec.w = sink
	if s.recKey != nil {
		sealer, serr := recording.NewSealer(ctx, sink, s.recKey, name)
		if serr != nil {
			f.Close()
			_ = os.Remove(path)
			return nil, serr
		}
		rec.w = sealer
	}
	return rec, nil
}

// Write records one whole instruction. Past the cap it refuses, and the
// bridge ends the session.
func (r *viewerRecording) Write(inst []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return os.ErrClosed
	}
	if r.max > 0 && r.raw+int64(len(inst)) > r.max {
		return errViewerRecordingLimit
	}
	if _, err := r.w.Write(inst); err != nil {
		return err
	}
	r.raw += int64(len(inst))
	return nil
}

// finish closes the file and returns its path, the SHA-256 of the stored
// bytes, and how many there are.
func (r *viewerRecording) finish() (string, string, int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		r.closed = true
		r.f.Close()
	}
	return r.path, hex.EncodeToString(r.hasher.Sum(nil)), r.stored
}

// watchForwardable is what a watcher's browser may send guacd: the protocol's
// own keep-alive and flow control. Everything else — key, mouse, clipboard,
// file and pipe streams, size, and the tunnel's internal instructions — is
// dropped here, whatever guacd would have done with it.
var watchForwardable = map[string]bool{"sync": true, "nop": true, "disconnect": true}

// watchInput filters one browser message down to the instructions a watcher
// may send, re-encoded; nil when nothing survives.
func watchInput(data []byte) []byte {
	var out []byte
	for _, inst := range guacd.DecodeAll(data) {
		if watchForwardable[inst.Opcode] {
			out = append(out, inst.Encode()...)
		}
	}
	return out
}

// watchOutput decides whether one guacd instruction reaches a watcher. The
// display does; the owner's CLIPBOARD does not — guacd hands every user of a
// connection the clipboard, and what an operator copies inside a privileged
// desktop is often a secret, which watching a screen does not otherwise
// reveal. A clipboard stream is dropped whole: its opening instruction and
// every blob and end on its stream index.
type watchOutput struct {
	clipStreams map[string]bool
}

func (o *watchOutput) forward(inst []byte) bool {
	in, ok := guacd.Decode(inst)
	if !ok {
		return true
	}
	switch in.Opcode {
	case "clipboard":
		if len(in.Args) > 0 {
			if o.clipStreams == nil {
				o.clipStreams = map[string]bool{}
			}
			o.clipStreams[in.Args[0]] = true
		}
		return false
	case "blob", "end":
		if len(in.Args) > 0 && o.clipStreams[in.Args[0]] {
			if in.Opcode == "end" {
				delete(o.clipStreams, in.Args[0])
			}
			return false
		}
	}
	return true
}

// sessionViewToken (POST /api/sessions/{id}/view-token) mints a single-use,
// 60-second watch token for a graphical session live on this replica. Asking
// first makes "no such graphical session" answerable before a WebSocket
// exists. Requires CapReadAudit — the capability the text stream takes.
func (s *Server) sessionViewToken(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, "graphical sessions are not configured")
		return
	}
	p := principalFrom(r.Context())
	if p.BreakGlass {
		// A break-glass session is for recovery, not supervision, and its
		// scope cannot be narrowed into a watch token.
		writeError(w, http.StatusForbidden, "a break-glass session cannot mint a watch token")
		return
	}
	if _, ok := s.viewerJoins.Load(id); !ok {
		s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:no-graphical-session-on-this-replica")
		writeError(w, http.StatusNotFound, "no graphical session with that id is live on this replica")
		return
	}
	token, sess, err := s.issueSessionTTL(r.Context(), p, auth.SessionScopeWatch, watchTokenTTL)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not mint a watch token")
		return
	}
	// id named a live registry entry, so it is the registry's own hex id.
	s.audit(r.Context(), "session.view_token", "session:"+id+" ttl:"+watchTokenTTL.String())
	writeJSON(w, http.StatusOK, map[string]any{"token": token, "expires_at": sess.ExpiresAt})
}

// sessionView (GET /api/sessions/{id}/view?token=&width=&height=) joins a live
// RDP/VNC session read-only and bridges it to the watcher's browser. The token
// comes from the query because browsers cannot set WebSocket headers; it is
// watch-scoped, spent on a successful join, and refused everywhere else.
func (s *Server) sessionView(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if s.guacdAddr == "" {
		writeError(w, http.StatusNotFound, "graphical sessions are not configured")
		return
	}
	token := r.URL.Query().Get("token")
	principal, err := s.resolver.Resolve(r.Context(), token)
	if err != nil {
		s.authFailed(w, r, "watch", "invalid or missing token")
		return
	}
	setActor(r.Context(), principal.Name)
	r = r.WithContext(withPrincipal(r.Context(), principal))
	if principal.NarrowScope() != auth.ScopeWatch {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:not-a-watch-token")
		writeError(w, http.StatusForbidden, "this endpoint takes a watch token (POST /api/sessions/{id}/view-token)")
		return
	}
	if reason, msg := s.sourceGates(r.Context(), principal, r); reason != "" {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" reason:"+reason)
		writeError(w, http.StatusForbidden, msg)
		return
	}
	if !principal.Can(auth.CapReadAudit) {
		s.audit(r.Context(), "authz.denied", r.Method+" "+r.URL.Path+" role:"+string(principal.Role))
		writeError(w, http.StatusForbidden, "your role does not permit watching sessions")
		return
	}
	v, ok := s.viewerJoins.Load(id)
	if !ok {
		s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:no-graphical-session-on-this-replica")
		writeError(w, http.StatusNotFound, "no graphical session with that id is live on this replica")
		return
	}
	j := v.(viewerJoin)
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	gconn, err := guacd.Connect(ctx, s.guacdAddr, guacd.Params{
		Protocol: j.protocol, Join: j.conn, ReadOnly: true,
		Width:  clampDim(atoiOr(r.URL.Query().Get("width"), 1024)),
		Height: clampDim(atoiOr(r.URL.Query().Get("height"), 768)),
	})
	if err != nil {
		s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:guacd-join-failed")
		writeError(w, http.StatusBadGateway, "could not join the session")
		return
	}
	defer gconn.Close()
	// guacd drops a parameter it did not advertise; a watcher on a guacd that
	// cannot make it read-only would be a second pair of hands on a privileged
	// desktop. Refuse rather than rely on the bridge's filter alone.
	if !gconn.Supports("read-only") {
		s.audit(r.Context(), "session.monitor", "session:"+auditField(id, 64)+" refused:read-only-unenforceable")
		writeError(w, http.StatusBadGateway, "guacd cannot make a watcher read-only")
		return
	}
	// Spend the token: it opened exactly one watch.
	_ = s.store.DeleteSession(context.WithoutCancel(r.Context()), auth.TokenHash(token))
	if !s.mustAudit(w, r.Context(), "session.monitor", fmt.Sprintf("session:%s protocol:%s target:%s actor:%s mode:read-only",
		id, j.protocol, j.target, j.actor)) { // id named a live registry entry
		return
	}
	ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"guacamole"}})
	if err != nil {
		return
	}
	defer ws.Close(websocket.StatusNormalClosure, "")

	// The watched session ending ends the watch, whatever guacd does.
	go func() {
		select {
		case <-j.done:
			cancel()
			gconn.Close()
		case <-ctx.Done():
		}
	}()
	uuid := tunnelUUID()
	if uuid == "" {
		uuid = gconn.ID
	}
	for _, inst := range guacamolePrelude(uuid, gconn.ID) {
		if err := ws.Write(ctx, websocket.MessageText, inst); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() { // guacd → watcher, less the owner's clipboard
		var out watchOutput
		for {
			inst, err := gconn.NextInstruction()
			if len(inst) > 0 && out.forward(inst) {
				if werr := ws.Write(ctx, websocket.MessageText, inst); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() { // watcher → guacd: keep-alive only
		for {
			_, data, err := ws.Read(ctx)
			if err != nil {
				break
			}
			if out := watchInput(data); out != nil {
				if _, werr := gconn.Write(out); werr != nil {
					break
				}
			}
		}
		done <- struct{}{}
	}()
	<-done
}
