// Package auditfwd streams the primary audit trail to an external SIEM as it
// grows. Where internal/alert fires a message on a specific event (break-glass,
// a risk spike) and the OCSF endpoint is pull-based, this is a continuous push:
// every audit row is forwarded, in order, as an RFC 5424 syslog message
// (https://datatracker.ietf.org/doc/html/rfc5424), an ArcSight CEF record
// (https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.4/cef-implementation-standard/)
// or an IBM QRadar LEEF 2.0 record
// (https://www.ibm.com/docs/en/dsm?topic=leef-overview), over UDP, TCP, or
// TLS with fail-closed certificate verification (RFC 5425 for the syslog
// format, https://datatracker.ietf.org/doc/html/rfc5425).
//
// It tails the trail from a durable cursor (the id of the last event forwarded,
// persisted in the settings store), so a restart resumes exactly where it left
// off — no gap, no replay. The cursor advances only after an event is written to
// the collector, so a transport failure re-sends from the last success on the
// next tick (spool-and-retry). In HA the whole pass runs under a Postgres leader
// lock, so N replicas do not each forward the same rows.
package auditfwd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/auditfmt"
	"github.com/morandeirachema/pamv1/internal/logging"
	"github.com/morandeirachema/pamv1/internal/store"
)

// cursorKey is the settings key holding the last-forwarded audit id. The leading
// underscore keeps it out of the config-override whitelist namespace.
const cursorKey = "_audit_forward_cursor"

// forwardLockKey is the advisory-lock key that serializes the forward pass across
// replicas ("pam_fwd" as bytes).
const forwardLockKey = 0x70616d5f667764

// Format is the wire format emitted to the collector.
type Format string

const (
	FormatRFC5424 Format = "rfc5424"
	FormatCEF     Format = "cef"
	FormatLEEF    Format = "leef"
)

// ParseFormat validates a format string, defaulting empty to RFC 5424.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case "", FormatRFC5424:
		return FormatRFC5424, nil
	case FormatCEF:
		return FormatCEF, nil
	case FormatLEEF:
		return FormatLEEF, nil
	default:
		return "", fmt.Errorf("invalid audit-forward format %q (want rfc5424, cef or leef)", s)
	}
}

// source is the slice of the store the forwarder needs (satisfied by store.Store).
type source interface {
	AuditSince(ctx context.Context, afterID int64, limit int) ([]store.AuditEvent, error)
	ListAudit(ctx context.Context, limit int) ([]store.AuditEvent, error)
	GetSetting(ctx context.Context, key string) (*store.Setting, error)
	PutSetting(ctx context.Context, s *store.Setting) error
	WithLeaderLock(ctx context.Context, key int64, fn func(context.Context) error) (bool, error)
}

// Config configures a Forwarder.
type Config struct {
	Network string // "udp", "tcp" or "tls" (RFC 5425 syslog over TLS)
	Addr    string // host:port of the SIEM collector
	Format  Format
	Tag     string // syslog APP-NAME / CEF device product (default "PAMv1")
	Host    string // syslog HOSTNAME (default the OS hostname)
	Batch   int    // max events per flush (default 500)
	// TLSCAFile, for the "tls" transport, is a PEM bundle the collector's
	// certificate must chain to (pinning); empty uses the system roots.
	// Verification is always on — the audit trail must not be streamed to an
	// unauthenticated endpoint, so there is deliberately no insecure switch.
	TLSCAFile string
}

// Forwarder pushes new audit events to a SIEM collector.
type Forwarder struct {
	src     source
	network string
	addr    string
	format  Format
	tag     string
	host    string
	batch   int
	dial    func(network, addr string) (net.Conn, error)
	log     *slog.Logger
}

// New builds a Forwarder, validating the transport and format. dial defaults to a
// timeout-bounded net dialer (a verifying tls.Dial for the "tls" transport);
// tests inject their own.
func New(src source, cfg Config) (*Forwarder, error) {
	if cfg.Addr == "" {
		return nil, fmt.Errorf("auditfwd: Addr is required")
	}
	if cfg.Network != "udp" && cfg.Network != "tcp" && cfg.Network != "tls" {
		return nil, fmt.Errorf("auditfwd: Network must be udp, tcp or tls (got %q)", cfg.Network)
	}
	format, err := ParseFormat(string(cfg.Format))
	if err != nil {
		return nil, err
	}
	f := &Forwarder{
		src: src, network: cfg.Network, addr: cfg.Addr, format: format,
		tag: cfg.Tag, host: cfg.Host, batch: cfg.Batch,
		log: logging.Component("auditfwd"),
	}
	if f.tag == "" {
		f.tag = "PAMv1"
	}
	if f.host == "" {
		if h, err := os.Hostname(); err == nil && h != "" {
			f.host = h
		} else {
			f.host = "-"
		}
	}
	if f.batch <= 0 {
		f.batch = 500
	}
	switch cfg.Network {
	case "tls":
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if cfg.TLSCAFile != "" {
			pem, err := os.ReadFile(cfg.TLSCAFile)
			if err != nil {
				return nil, fmt.Errorf("auditfwd: read TLS CA bundle: %w", err)
			}
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("auditfwd: no certificates in TLS CA bundle %s", cfg.TLSCAFile)
			}
			tlsCfg.RootCAs = pool
		}
		f.dial = func(_, addr string) (net.Conn, error) {
			return tls.DialWithDialer(&net.Dialer{Timeout: 5 * time.Second}, "tcp", addr, tlsCfg)
		}
	default:
		f.dial = func(network, addr string) (net.Conn, error) {
			return net.DialTimeout(network, addr, 5*time.Second)
		}
	}
	return f, nil
}

// Run forwards new audit events every interval until ctx is cancelled. Each pass
// runs under the leader lock so only one replica forwards. It does an immediate
// first pass so a freshly enabled forwarder does not wait a full interval.
func (f *Forwarder) Run(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		if _, err := f.src.WithLeaderLock(ctx, forwardLockKey, f.Flush); err != nil && ctx.Err() == nil {
			f.log.Warn("audit forward pass failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// Flush sends every audit event newer than the cursor, advancing (and persisting)
// the cursor as it goes. It drains in batches; a dial or write failure stops the
// pass with the cursor at the last event actually delivered, so the next pass
// resumes there (spool-and-retry).
func (f *Forwarder) Flush(ctx context.Context) error {
	cursor, err := f.loadCursor(ctx)
	if err != nil {
		return err
	}
	for {
		events, err := f.src.AuditSince(ctx, cursor, f.batch)
		if err != nil {
			return err
		}
		if len(events) == 0 {
			return nil
		}
		conn, err := f.dial(f.network, f.addr)
		if err != nil {
			return err // collector unreachable; retry next tick, cursor unchanged
		}
		sent := cursor
		for _, e := range events {
			_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, werr := conn.Write(f.frame(f.format.render(e, f.tag, f.host))); werr != nil {
				conn.Close()
				if sent != cursor {
					_ = f.saveCursor(ctx, sent) // persist partial progress
				}
				return werr
			}
			sent = e.ID
		}
		conn.Close()
		cursor = sent
		if err := f.saveCursor(ctx, cursor); err != nil {
			return err
		}
		if len(events) < f.batch {
			return nil // drained
		}
	}
}

// loadCursor returns the last-forwarded id. On first run (no cursor persisted) it
// initializes to the current max audit id and persists it, so enabling forwarding
// starts from "now" rather than replaying the entire history into the SIEM.
func (f *Forwarder) loadCursor(ctx context.Context) (int64, error) {
	s, err := f.src.GetSetting(ctx, cursorKey)
	if err == nil {
		return strconv.ParseInt(s.Value, 10, 64)
	}
	if err != store.ErrNotFound {
		return 0, err
	}
	var start int64
	if latest, lerr := f.src.ListAudit(ctx, 1); lerr == nil && len(latest) > 0 {
		start = latest[0].ID
	}
	return start, f.saveCursor(ctx, start)
}

// saveCursor persists the cursor as a non-secret setting.
func (f *Forwarder) saveCursor(ctx context.Context, id int64) error {
	return f.src.PutSetting(ctx, &store.Setting{Key: cursorKey, Value: strconv.FormatInt(id, 10)})
}

// frame wraps one rendered record for the transport. UDP and TCP use
// newline-delimited records (RFC 6587 non-transparent framing, which every
// CEF/LEEF collector also expects). Syslog over TLS uses the octet-counted
// framing RFC 5425 §4.3 REQUIRES ("MSG-LEN SP MSG") — but only for the syslog
// format: CEF and LEEF records are not syslog messages, so they stay
// newline-delimited on every transport.
func (f *Forwarder) frame(msg string) []byte {
	if f.network == "tls" && f.format == FormatRFC5424 {
		return []byte(strconv.Itoa(len(msg)) + " " + msg)
	}
	return []byte(msg + "\n")
}

// render formats an audit event in the forwarder's wire format.
func (fm Format) render(e store.AuditEvent, tag, host string) string {
	switch fm {
	case FormatCEF:
		return renderCEF(e, tag)
	case FormatLEEF:
		return renderLEEF(e, tag)
	}
	return renderRFC5424(e, tag, host)
}

// renderRFC5424 formats an event as an RFC 5424 syslog line. PRI = facility 13
// (log audit) * 8 + severity 6 (informational) = 110. Actor/action/detail are
// sanitized so a name carrying CR/LF (e.g. from a directory claim) cannot forge
// extra syslog records.
func renderRFC5424(e store.AuditEvent, tag, host string) string {
	return fmt.Sprintf("<110>1 %s %s %s - %s - actor=%s detail=%q",
		e.TS.UTC().Format(time.RFC3339), auditfmt.OneLine(host), auditfmt.OneLine(tag),
		auditfmt.OneLine(e.Action), auditfmt.OneLine(e.Actor), auditfmt.OneLine(e.Detail))
}

// renderCEF formats an event as an ArcSight CEF record. Header fields escape '|'
// and '\'; extension values escape '=' and '\'. rt is milliseconds since epoch.
func renderCEF(e store.AuditEvent, tag string) string {
	sig := cefHeader(e.Action)
	return fmt.Sprintf("CEF:0|PAMv1|%s|1|%s|%s|3|rt=%d suser=%s msg=%s",
		cefHeader(tag), sig, sig, e.TS.UnixMilli(),
		cefExt(e.Actor), cefExt(e.Detail))
}

// renderLEEF formats an event as an IBM QRadar LEEF 2.0 record: a pipe-headed
// prologue then tab-separated key=value attributes. devTime is milliseconds
// since epoch, matching CEF's rt. Header fields escape '|'; attribute values
// strip tabs (the delimiter) and CR/LF, so an actor name carrying either cannot
// forge an attribute or a record.
func renderLEEF(e store.AuditEvent, tag string) string {
	return fmt.Sprintf("LEEF:2.0|PAMv1|%s|1|%s|devTime=%d\tusrName=%s\tmsg=%s",
		leefHeader(tag), leefHeader(e.Action), e.TS.UnixMilli(),
		leefAttr(e.Actor), leefAttr(e.Detail))
}

// leefHeader escapes the LEEF header-field metacharacters (\ and |).
func leefHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\t", " ", `\`, `\\`, "|", `\|`).Replace(s)
}

// leefAttr strips the attribute delimiter and record terminators from a value.
func leefAttr(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(s)
}

// cefHeader escapes the CEF header-field metacharacters (\ and |).
func cefHeader(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", `\`, `\\`, "|", `\|`).Replace(s)
}

// cefExt escapes the CEF extension-value metacharacters (\ and =).
func cefExt(s string) string {
	return strings.NewReplacer("\r", " ", "\n", " ", `\`, `\\`, "=", `\=`).Replace(s)
}
