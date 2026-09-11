package postgres

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/inventedsarawak/hyperion/apps/cortex/internal/domain/ports"
)

func TestLostRacesAreConflictsAndRealFailuresAreNot(t *testing.T) {
	for code, retry := range map[string]bool{
		"23505": true,  // unique violation: two writers claimed one id
		"40P01": true,  // deadlock: Postgres aborted one of two waiting writers
		"40001": true,  // serialization failure
		"23503": false, // foreign key violation: a bug, not a race
		"42P01": false, // undefined table: a broken deployment
	} {
		err := asConflict(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: code, Message: "m"}))
		if got := errors.Is(err, ports.ErrConflict); got != retry {
			t.Errorf("code %s: retried = %v, want %v", code, got, retry)
		}
	}
	if plain := errors.New("connection reset"); asConflict(plain) != plain {
		t.Error("a non-Postgres error must pass through unchanged")
	}
}
