-- The fingerprint of the key a server backup was sealed with: a backup that
-- no longer opens after the key was replaced reads "key lost", not "does not
-- match". Rows from before this column have '' (unknown key).
ALTER TABLE server_backup ADD COLUMN key_fingerprint TEXT NOT NULL DEFAULT '';
