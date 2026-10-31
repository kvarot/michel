-- The network rules Michel itself wrote for the servers it added (lowercase
-- host, purpose). A rule written by hand in the policy file is never in this
-- table, so removing a server never removes it.
CREATE TABLE target_rule (
  host TEXT NOT NULL,
  purpose TEXT NOT NULL,
  PRIMARY KEY (host, purpose)
);
