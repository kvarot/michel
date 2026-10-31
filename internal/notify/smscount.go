package notify

import (
	"context"
	"fmt"
	"time"

	"github.com/kvarot/michel/internal/store"
)

// SMSCounter counts the SMS sent in a day, so Michel keeps to the daily cap.
type SMSCounter interface {
	// Take reserves one SMS of the day of now when fewer than max were
	// reserved, and tells whether it did.
	Take(ctx context.Context, now time.Time, max int) (bool, error)
	// Release gives back a reservation whose SMS was not sent.
	Release(ctx context.Context, now time.Time) error
}

// StoreCounter keeps the count in the store (table sms_count, one row per
// local day).
type StoreCounter struct{ S *store.Store }

// day is the calendar day of now in local time: the cap resets at the
// user's midnight, not at UTC midnight.
func day(now time.Time) string { return now.In(time.Local).Format("2006-01-02") }

// Take implements SMSCounter. The increment is one conditional UPDATE, so two
// processes never go above max.
func (c StoreCounter) Take(ctx context.Context, now time.Time, max int) (bool, error) {
	db := c.S.DB()
	if _, err := db.ExecContext(ctx, `INSERT INTO sms_count (day, n) VALUES (?, 0) ON CONFLICT (day) DO NOTHING`, day(now)); err != nil {
		return false, fmt.Errorf("cannot count the sms: %w", err)
	}
	res, err := db.ExecContext(ctx, `UPDATE sms_count SET n = n + 1 WHERE day = ? AND n < ?`, day(now), max)
	if err != nil {
		return false, fmt.Errorf("cannot count the sms: %w", err)
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// Release implements SMSCounter.
func (c StoreCounter) Release(ctx context.Context, now time.Time) error {
	_, err := c.S.DB().ExecContext(ctx, `UPDATE sms_count SET n = n - 1 WHERE day = ? AND n > 0`, day(now))
	return err
}
