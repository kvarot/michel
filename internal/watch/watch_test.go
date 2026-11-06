package watch

import (
	"testing"
	"time"
	_ "time/tzdata"
)

var paris = func() *time.Location {
	l, err := time.LoadLocation("Europe/Paris")
	if err != nil {
		panic(err)
	}
	return l
}()

func at(day, hm string) time.Time {
	t, err := time.ParseInLocation("2006-01-02 15:04", day+" "+hm, paris)
	if err != nil {
		panic(err)
	}
	return t
}

func TestDueAndNext(t *testing.T) {
	for _, c := range []struct {
		name     string
		last     time.Time
		has      bool
		now      time.Time
		due      bool
		nextWant time.Time
	}{
		{"never scanned, before the hour", time.Time{}, false, at("2026-11-05", "06:59"), false, at("2026-11-05", "07:00")},
		{"never scanned, at the hour", time.Time{}, false, at("2026-11-05", "07:00"), true, at("2026-11-05", "07:00")},
		{"scanned yesterday, after the hour", at("2026-11-04", "07:01"), true, at("2026-11-05", "09:00"), true, at("2026-11-05", "07:00")},
		{"scanned today after the hour", at("2026-11-05", "07:02"), true, at("2026-11-05", "09:00"), false, at("2026-11-06", "07:00")},
		{"checked by hand after the hour", at("2026-11-05", "07:30"), true, at("2026-11-05", "07:45"), false, at("2026-11-06", "07:00")},
		{"scanned today before the hour", at("2026-11-05", "06:00"), true, at("2026-11-05", "08:00"), true, at("2026-11-05", "07:00")},
		{"computer off at the hour", at("2026-11-03", "07:00"), true, at("2026-11-05", "22:00"), true, at("2026-11-05", "07:00")},
	} {
		if got := Due(c.last, c.has, c.now, 7, 0); got != c.due {
			t.Errorf("%s: due = %v", c.name, got)
		}
		if got := Next(c.last, c.has, c.now, 7, 0); !got.Equal(c.nextWant) {
			t.Errorf("%s: next = %v, want %v", c.name, got, c.nextWant)
		}
	}
}

// A clock that goes back does not run again a check already done that day.
func TestDueClockGoesBack(t *testing.T) {
	last := at("2026-11-05", "07:20")
	for _, now := range []time.Time{at("2026-11-05", "07:10"), at("2026-11-05", "06:00"), at("2026-11-04", "08:00")} {
		if Due(last, true, now, 7, 0) {
			t.Errorf("due again at %v", now)
		}
	}
}

// The hour holds across a change of daylight saving time.
func TestDayStartAcrossDaylightSaving(t *testing.T) {
	now := at("2026-10-25", "12:00") // the clocks went back that night
	if got := DayStart(now, 7, 0); got.Hour() != 7 || got.Day() != 25 {
		t.Errorf("day start = %v", got)
	}
	if got := Next(at("2026-10-25", "07:05"), true, now, 7, 0); got.Hour() != 7 || got.Day() != 26 {
		t.Errorf("next = %v", got)
	}
}
