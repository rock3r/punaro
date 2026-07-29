package postgres

import (
	"context"
	"errors"
)

// RemoteMCPPrincipalActive reports whether a configured remote-MCP subject
// binding names an existing, enabled principal. It intentionally exposes no
// project authority: later transport requests use the normal capability checks.
func (d *Database) RemoteMCPPrincipalActive(ctx context.Context, principalID string) (bool, error) {
	if !validOpaqueID(principalID) {
		return false, errors.New("remote MCP principal ID is invalid")
	}
	var active bool
	if err := d.db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM auth.principals WHERE id = $1 AND disabled_at IS NULL)`, principalID).Scan(&active); err != nil {
		return false, err
	}
	return active, nil
}
