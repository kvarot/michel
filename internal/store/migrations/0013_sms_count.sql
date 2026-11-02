-- SMS sent per day (UTC), to keep to the daily cap. One row per day.
CREATE TABLE sms_count (
  day TEXT PRIMARY KEY,
  n INTEGER NOT NULL DEFAULT 0
);
