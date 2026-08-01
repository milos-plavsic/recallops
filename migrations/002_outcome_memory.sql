USE recallops;

ALTER TABLE memories ADD COLUMN IF NOT EXISTS source_incident_id UUID NULL;
CREATE UNIQUE INDEX IF NOT EXISTS memories_source_incident ON memories (source_incident_id);
