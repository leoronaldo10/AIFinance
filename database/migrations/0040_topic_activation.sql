-- Keep old topic rows for history while the industry pack controls the public directory.
ALTER TABLE topics ADD COLUMN active boolean NOT NULL DEFAULT true;
