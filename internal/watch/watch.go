// Package watch is the daily watch of michel serve: once a day, from the hour
// of the policy (watch.scan_at), it reads the enabled sources and checks every
// active project whose watch is on. What is due is computed from the database
// (the newest scan of each project), in local time, so a restart loses nothing
// and does nothing twice.
package watch

import "time"

// DayStart is the hour of the watch on the local day of now.
func DayStart(now time.Time, hour, minute int) time.Time {
	y, m, d := now.Date()
	return time.Date(y, m, d, hour, minute, 0, 0, now.Location())
}

// Due says whether a project whose newest scan started at last (has false:
// never scanned) is due at now: the hour of the day has come and no scan
// started since. A check started by hand after the hour counts. A clock that
// goes back does not make a project due again: its scan is still after the
// hour of the day the clock now shows.
func Due(last time.Time, has bool, now time.Time, hour, minute int) bool {
	start := DayStart(now, hour, minute)
	if now.Before(start) {
		return false
	}
	return !has || last.Before(start)
}

// Next is when the watch checks the project next: today's hour when it is
// still to come or the project is due (at the next look of serve), else the
// hour of the next day.
func Next(last time.Time, has bool, now time.Time, hour, minute int) time.Time {
	start := DayStart(now, hour, minute)
	if now.Before(start) || !has || last.Before(start) {
		return start
	}
	y, m, d := now.Date()
	return time.Date(y, m, d+1, hour, minute, 0, 0, now.Location())
}
