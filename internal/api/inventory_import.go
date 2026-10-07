package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/inventorycsv"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Bulk inventory import (Phase 278).
//
// Every row is REPLAYED through the class's own create handler — the same
// function POST /api/targets (or /credentials, /safes, /users, a target's
// /grants) runs — under the caller's identity. So an imported object is
// validated, guarded and audited exactly as one created by hand: there is
// no second copy of the rules to drift, a credential's secret is encrypted
// under the same AAD by the same code, and every row leaves its own
// target.create / credential.create / … audit row. The import route itself
// carries the create route's capability.
//
// Import only creates. A row whose object already exists is reported
// `exists` and left untouched, so re-running a file is safe and an import
// can never silently rewrite policy on an existing object.

// maxImportBytes bounds the uploaded file (a credentials file may carry
// secrets of file type, each itself capped by PAM_CREDENTIAL_FILE_MAX_KB).
const maxImportBytes = 16 << 20

// importRow is one row's outcome. It never carries a secret back.
type importRow struct {
	Line   int    `json:"line"`
	Name   string `json:"name"`
	Status string `json:"status"` // created | exists | error
	ID     int64  `json:"id,omitempty"`
	Error  string `json:"error,omitempty"`
	// Token is a new user's API token, returned once, as POST /api/users
	// returns it.
	Token string `json:"token,omitempty"`
}

type importResult struct {
	Class   string      `json:"class"`
	Created int         `json:"created"`
	Exists  int         `json:"exists"`
	Failed  int         `json:"failed"`
	Rows    []importRow `json:"rows"`
}

// rowRecorder captures a replayed handler's response.
type rowRecorder struct {
	h    http.Header
	code int
	body bytes.Buffer
}

func (rr *rowRecorder) Header() http.Header { return rr.h }
func (rr *rowRecorder) WriteHeader(c int) {
	if rr.code == 0 {
		rr.code = c
	}
}
func (rr *rowRecorder) Write(b []byte) (int, error) {
	if rr.code == 0 {
		rr.code = http.StatusOK
	}
	return rr.body.Write(b)
}

// replay runs handler h as if the caller had sent body to method path,
// keeping the caller's context — and so its principal — and the request's
// other headers. It returns the status, the decoded JSON object (nil when
// the response had none) and the handler's error message.
func replay(r *http.Request, h http.HandlerFunc, method, path string, pathValues map[string]string, body any) (int, map[string]any, string) {
	b, err := json.Marshal(body)
	if err != nil {
		return http.StatusInternalServerError, nil, err.Error()
	}
	req := r.Clone(r.Context())
	req.Method = method
	req.URL = &url.URL{Path: path}
	req.RequestURI = path
	req.Body = io.NopCloser(bytes.NewReader(b))
	req.ContentLength = int64(len(b))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range pathValues {
		req.SetPathValue(k, v)
	}
	rec := &rowRecorder{h: http.Header{}}
	h(rec, req)
	if rec.code == 0 {
		rec.code = http.StatusOK
	}
	var out map[string]any
	_ = json.Unmarshal(rec.body.Bytes(), &out)
	msg, _ := out["error"].(string)
	return rec.code, out, msg
}

// importInventory returns the handler that imports class c.
func (s *Server) importInventory(c inventorycsv.Class) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rows, err := inventorycsv.Read(c, http.MaxBytesReader(w, r.Body, maxImportBytes))
		if err != nil {
			var mbe *http.MaxBytesError
			if errors.As(err, &mbe) {
				writeError(w, http.StatusRequestEntityTooLarge, "file exceeds 16 MiB")
				return
			}
			writeError(w, http.StatusUnprocessableEntity, "csv: "+err.Error())
			return
		}
		imp := &inventoryImport{s: s, r: r}
		if err := imp.load(); err != nil {
			storeError(w, err)
			return
		}
		res := importResult{Class: c.Name, Rows: make([]importRow, 0, len(rows))}
		for _, row := range rows {
			out := imp.row(c, row)
			switch out.Status {
			case "created":
				res.Created++
			case "exists":
				res.Exists++
			default:
				res.Failed++
			}
			res.Rows = append(res.Rows, out)
		}
		s.audit(ctx, "inventory.import", fmt.Sprintf("class:%s rows:%d created:%d exists:%d failed:%d",
			c.Name, len(rows), res.Created, res.Exists, res.Failed))
		writeJSON(w, http.StatusOK, res)
	}
}

// inventoryImport is one import's view of what already exists, refreshed
// as rows create objects so a later row may refer to an earlier one.
type inventoryImport struct {
	s       *Server
	r       *http.Request
	targets map[string]store.Target
	safes   map[string]store.Safe
	users   map[string]bool
	creds   map[string]int64 // "target\x00username" -> id
}

func (imp *inventoryImport) load() error {
	ctx := imp.r.Context()
	_, targets, safes, err := imp.s.loadInventoryNames(ctx)
	if err != nil {
		return err
	}
	users, err := imp.s.store.ListUsers(ctx, 0, 0)
	if err != nil {
		return err
	}
	creds, err := imp.s.store.ListCredentialsMeta(ctx, 0, 0, 0)
	if err != nil {
		return err
	}
	imp.targets, imp.safes, imp.users, imp.creds = map[string]store.Target{}, map[string]store.Safe{}, map[string]bool{}, map[string]int64{}
	byID := map[int64]string{}
	for _, t := range targets {
		imp.targets[t.Name] = t
		byID[t.ID] = t.Name
	}
	for _, sf := range safes {
		imp.safes[sf.Name] = sf
	}
	for _, u := range users {
		imp.users[u.Username] = true
	}
	for _, c := range creds {
		imp.creds[byID[c.TargetID]+"\x00"+c.Username] = c.ID
	}
	return nil
}

func failed(line int, name, msg string) importRow {
	return importRow{Line: line, Name: name, Status: "error", Error: msg}
}

// row converts one CSV row to the class's create body and replays it.
func (imp *inventoryImport) row(c inventorycsv.Class, row inventorycsv.Row) importRow {
	switch c.Name {
	case inventorycsv.Safes.Name:
		return imp.safe(row)
	case inventorycsv.Targets.Name:
		return imp.target(row)
	case inventorycsv.Credentials.Name:
		return imp.credential(row)
	case inventorycsv.Users.Name:
		return imp.user(row)
	case inventorycsv.Grants.Name:
		return imp.grant(row)
	}
	return failed(row.Line, "", "unknown class")
}

// bools reads the named boolean columns, or reports the first bad one.
func bools(row inventorycsv.Row, cols ...string) (map[string]bool, string) {
	out := map[string]bool{}
	for _, col := range cols {
		v, err := inventorycsv.Bool(row.Get(col))
		if err != nil {
			return nil, col + ": " + err.Error()
		}
		out[col] = v
	}
	return out, ""
}

func created(line int, name string, code int, body map[string]any, msg string) importRow {
	if code != http.StatusCreated {
		if msg == "" {
			msg = http.StatusText(code)
		}
		return failed(line, name, msg)
	}
	id, _ := body["id"].(float64)
	return importRow{Line: line, Name: name, Status: "created", ID: int64(id)}
}

func (imp *inventoryImport) safe(row inventorycsv.Row) importRow {
	name := row.Get("name")
	if _, ok := imp.safes[name]; ok {
		return importRow{Line: row.Line, Name: name, Status: "exists"}
	}
	b, bad := bools(row, "require_approval", "require_session_mfa")
	if bad != "" {
		return failed(row.Line, name, bad)
	}
	minApprovers, err := inventorycsv.Int(row.Get("min_approvers"))
	if err != nil {
		return failed(row.Line, name, "min_approvers: "+err.Error())
	}
	code, body, msg := replay(imp.r, imp.s.createSafe, http.MethodPost, "/api/safes", nil, map[string]any{
		"name": name, "description": row.Get("description"), "require_approval": b["require_approval"],
		"min_approvers": minApprovers, "require_session_mfa": b["require_session_mfa"], "approval_tiers": row.Get("approval_tiers"),
	})
	out := created(row.Line, name, code, body, msg)
	if out.Status == "created" {
		imp.safes[name] = store.Safe{ID: out.ID, Name: name}
	}
	return out
}

// labelsMap splits a "k=v,k=v" cell strictly: a term with no "=" is an
// error here, not dropped, because labels are an authorization input and a
// typo that vanished would leave a target outside a deny rule. The target
// handler validates each part.
func labelsMap(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, term := range strings.Split(s, ",") {
		term = strings.TrimSpace(term)
		if term == "" {
			continue
		}
		k, v, ok := strings.Cut(term, "=")
		if !ok {
			return nil, fmt.Errorf("label %q is not key=value", term)
		}
		out[strings.TrimSpace(k)] = strings.TrimSpace(v)
	}
	return out, nil
}

func (imp *inventoryImport) target(row inventorycsv.Row) importRow {
	name := row.Get("name")
	if _, ok := imp.targets[name]; ok {
		return importRow{Line: row.Line, Name: name, Status: "exists"}
	}
	b, bad := bools(row, "require_approval", "require_session_mfa", "critical")
	if bad != "" {
		return failed(row.Line, name, bad)
	}
	port, err := inventorycsv.Int(row.Get("port"))
	if err != nil {
		return failed(row.Line, name, "port: "+err.Error())
	}
	labels, err := labelsMap(row.Get("labels"))
	if err != nil {
		return failed(row.Line, name, err.Error())
	}
	// Resolve the safe BEFORE creating anything: a row naming a safe that
	// does not exist must not leave a target behind outside it.
	var safeID *int64
	if sn := row.Get("safe"); sn != "" {
		sf, ok := imp.safes[sn]
		if !ok {
			return failed(row.Line, name, "safe "+strconv.Quote(sn)+" does not exist")
		}
		safeID = &sf.ID
	}
	code, body, msg := replay(imp.r, imp.s.createTarget, http.MethodPost, "/api/targets", nil, map[string]any{
		"name": name, "host": row.Get("host"), "port": port, "os_type": row.Get("os_type"), "protocol": row.Get("protocol"),
		"require_approval": b["require_approval"], "require_session_mfa": b["require_session_mfa"], "critical": b["critical"],
		"labels": labels, "approval_tiers": row.Get("approval_tiers"), "rights": row.Get("rights"),
		"rdp_clipboard": row.Get("rdp_clipboard"), "rdp_clipboard_audit": row.Get("rdp_clipboard_audit"),
	})
	out := created(row.Line, name, code, body, msg)
	if out.Status != "created" {
		return out
	}
	imp.targets[name] = store.Target{ID: out.ID, Name: name, Protocol: row.Get("protocol")}
	if safeID != nil {
		id := strconv.FormatInt(out.ID, 10)
		if code, _, msg := replay(imp.r, imp.s.setTargetSafe, http.MethodPut, "/api/targets/"+id+"/safe",
			map[string]string{"id": id}, map[string]any{"safe_id": *safeID}); code != http.StatusNoContent {
			// The target exists now; say so, and why it is not in its safe,
			// rather than reporting a clean failure that would invite a
			// re-run to create it twice.
			out.Status = "error"
			out.Error = "created, but not placed in safe " + strconv.Quote(row.Get("safe")) + ": " + msg
		}
	}
	return out
}

func (imp *inventoryImport) credential(row inventorycsv.Row) importRow {
	tn, user := row.Get("target"), row.Get("username")
	name := tn + "/" + user
	t, ok := imp.targets[tn]
	if !ok {
		return failed(row.Line, name, "target "+strconv.Quote(tn)+" does not exist")
	}
	if _, ok := imp.creds[tn+"\x00"+user]; ok {
		return importRow{Line: row.Line, Name: name, Status: "exists"}
	}
	b, bad := bools(row, "provisioner")
	if bad != "" {
		return failed(row.Line, name, bad)
	}
	code, body, msg := replay(imp.r, imp.s.createCredential, http.MethodPost, "/api/credentials", nil, map[string]any{
		"target_id": t.ID, "username": user, "secret_type": row.Get("secret_type"),
		"secret": row.Get("secret"), "provisioner": b["provisioner"],
	})
	out := created(row.Line, name, code, body, msg)
	if out.Status == "created" {
		imp.creds[tn+"\x00"+user] = out.ID
	}
	return out
}

func (imp *inventoryImport) user(row inventorycsv.Row) importRow {
	name := row.Get("username")
	if imp.users[name] {
		return importRow{Line: row.Line, Name: name, Status: "exists"}
	}
	ttl, err := inventorycsv.Int(row.Get("token_ttl_hours"))
	if err != nil {
		return failed(row.Line, name, "token_ttl_hours: "+err.Error())
	}
	code, body, msg := replay(imp.r, imp.s.createUser, http.MethodPost, "/api/users", nil, map[string]any{
		"username": name, "role": row.Get("role"), "ip_allowlist": row.Get("ip_allowlist"),
		"device_fingerprint": row.Get("device_fingerprint"), "slack_user_id": row.Get("slack_user_id"),
		"manager": row.Get("manager"), "token_ttl_hours": ttl,
	})
	out := created(row.Line, name, code, body, msg)
	if out.Status == "created" {
		imp.users[name] = true
		out.Token, _ = body["token"].(string)
	}
	return out
}

func (imp *inventoryImport) grant(row inventorycsv.Row) importRow {
	tn, st, subj := row.Get("target"), row.Get("subject_type"), row.Get("subject")
	name := tn + "/" + st + ":" + subj
	t, ok := imp.targets[tn]
	if !ok {
		return failed(row.Line, name, "target "+strconv.Quote(tn)+" does not exist")
	}
	in := map[string]any{"subject_type": st, "subject": subj, "time_frame": row.Get("time_frame"), "rights": row.Get("rights")}
	var credID *int64
	if cu := row.Get("credential_user"); cu != "" {
		id, ok := imp.creds[tn+"\x00"+cu]
		if !ok {
			return failed(row.Line, name, "credential "+strconv.Quote(cu)+" does not exist on "+tn)
		}
		credID = &id
		in["credential_id"] = id
	}
	if e := row.Get("expires_at"); e != "" {
		ts, err := time.Parse(time.RFC3339, e)
		if err != nil {
			return failed(row.Line, name, "expires_at must be RFC3339")
		}
		in["expires_at"] = ts
	}
	// A grant has no name; it exists when the same subject already holds a
	// direct grant at the same scope on the target.
	grants, err := imp.s.store.ListTargetGrants(imp.r.Context(), t.ID)
	if err != nil {
		return failed(row.Line, name, "cannot read the target's grants")
	}
	for _, g := range grants {
		if g.SubjectType == st && g.Subject == subj && sameCred(g.CredentialID, credID) {
			return importRow{Line: row.Line, Name: name, Status: "exists", ID: g.ID}
		}
	}
	id := strconv.FormatInt(t.ID, 10)
	code, body, msg := replay(imp.r, imp.s.createTargetGrant, http.MethodPost, "/api/targets/"+id+"/grants",
		map[string]string{"id": id}, in)
	return created(row.Line, name, code, body, msg)
}

func sameCred(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}
