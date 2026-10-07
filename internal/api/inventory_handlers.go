package api

import (
	"context"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/morandeirachema/pamv1/internal/inventorycsv"
	"github.com/morandeirachema/pamv1/internal/store"
)

// Bulk inventory export (Phase 278). One CSV per class, objects named rather
// than numbered, gated by the capability of the list route each class
// already has — an export reveals nothing that listing did not. Secrets are
// never read: credentials come from ListCredentialsMeta, which does not
// select the ciphertext, and the secret column is always empty.

// inventoryNames resolves ids to names for the cross-references.
type inventoryNames struct {
	targets map[int64]string
	safes   map[int64]store.Safe
}

func (s *Server) loadInventoryNames(ctx context.Context) (inventoryNames, []store.Target, []store.Safe, error) {
	targets, err := s.store.ListTargets(ctx, 0, 0)
	if err != nil {
		return inventoryNames{}, nil, nil, err
	}
	safes, err := s.store.ListSafes(ctx, 0, 0)
	if err != nil {
		return inventoryNames{}, nil, nil, err
	}
	n := inventoryNames{targets: map[int64]string{}, safes: map[int64]store.Safe{}}
	for _, t := range targets {
		n.targets[t.ID] = t.Name
	}
	for _, sf := range safes {
		n.safes[sf.ID] = sf
	}
	return n, targets, safes, nil
}

// exportInventory returns the handler that writes class c as CSV.
func (s *Server) exportInventory(c inventorycsv.Class) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		rows, err := s.inventoryRows(ctx, c)
		if err != nil {
			storeError(w, err)
			return
		}
		s.audit(ctx, "inventory.export", "class:"+c.Name+" rows:"+strconv.Itoa(len(rows)))
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="pamv1-`+c.Name+`.csv"`)
		if err := inventorycsv.Write(w, c, rows); err != nil {
			s.log.Error("inventory export", "class", c.Name, "err", err)
		}
	}
}

// inventoryRows builds class c's rows in c.Columns order.
func (s *Server) inventoryRows(ctx context.Context, c inventorycsv.Class) ([][]string, error) {
	names, targets, safes, err := s.loadInventoryNames(ctx)
	if err != nil {
		return nil, err
	}
	b := inventorycsv.FormatBool
	var rows [][]string
	switch c.Name {
	case inventorycsv.Safes.Name:
		for _, sf := range safes {
			// A personal safe is one user's private vault (Phase 139); written
			// out without that flag it would import back as a SHARED safe, so
			// it is not exported at all.
			if sf.Personal {
				continue
			}
			rows = append(rows, []string{sf.Name, sf.Description, b(sf.RequireApproval), strconv.Itoa(sf.MinApprovers), b(sf.RequireSessionMFA), sf.ApprovalTiers})
		}
	case inventorycsv.Targets.Name:
		for _, t := range targets {
			safe := ""
			if t.SafeID != nil {
				// A target in a personal safe exports with no safe, for the
				// reason the safe itself is not exported.
				if sf, ok := names.safes[*t.SafeID]; ok && !sf.Personal {
					safe = sf.Name
				}
			}
			rows = append(rows, []string{t.Name, t.Host, strconv.Itoa(t.Port), t.OSType, t.Protocol, safe,
				b(t.RequireApproval), b(t.RequireSessionMFA), b(t.Critical), t.Labels, t.ApprovalTiers, t.Rights,
				t.RDPClipboard, t.RDPClipboardAudit})
		}
	case inventorycsv.Credentials.Name:
		creds, err := s.store.ListCredentialsMeta(ctx, 0, 0, 0)
		if err != nil {
			return nil, err
		}
		for _, cr := range creds {
			rows = append(rows, []string{names.targets[cr.TargetID], cr.Username, cr.SecretType, b(cr.Provisioner), ""})
		}
	case inventorycsv.Users.Name:
		users, err := s.store.ListUsers(ctx, 0, 0)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			rows = append(rows, []string{u.Username, u.Role, u.IPAllowlist, u.DeviceFingerprint, u.SlackUserID, u.Manager, ""})
		}
	case inventorycsv.Grants.Name:
		creds, err := s.store.ListCredentialsMeta(ctx, 0, 0, 0)
		if err != nil {
			return nil, err
		}
		credUser := map[int64]string{}
		for _, cr := range creds {
			credUser[cr.ID] = cr.Username
		}
		for _, t := range targets {
			grants, err := s.store.ListTargetGrants(ctx, t.ID)
			if err != nil {
				return nil, err
			}
			for _, g := range grants {
				cu, exp := "", ""
				if g.CredentialID != nil {
					cu = credUser[*g.CredentialID]
				}
				if g.ExpiresAt != nil {
					exp = g.ExpiresAt.UTC().Format(time.RFC3339)
				}
				rows = append(rows, []string{t.Name, g.SubjectType, g.Subject, cu, exp, g.TimeFrame, g.Rights})
			}
		}
	}
	// Stable output: the same inventory exports byte-identically.
	sort.SliceStable(rows, func(i, j int) bool { return strings.Join(rows[i], "\x00") < strings.Join(rows[j], "\x00") })
	return rows, nil
}
