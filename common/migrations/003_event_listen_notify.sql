-- ============================================================================
-- Event LISTEN/NOTIFY trigger for real-time WebSocket streaming
-- ============================================================================

-- Function to notify when new events are inserted
CREATE OR REPLACE FUNCTION notify_event_inserted()
RETURNS TRIGGER AS $$
BEGIN
    PERFORM pg_notify('events_inserted', json_build_object(
        'id', NEW.id::text,
        'tenant_id', NEW.tenant_id::text
    )::text);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Attach trigger to events partitioned table
-- In PostgreSQL 11+, triggers on partitioned tables fire for partition inserts
DROP TRIGGER IF EXISTS event_insert_notify ON events;
CREATE TRIGGER event_insert_notify
    AFTER INSERT ON events
    FOR EACH ROW
    EXECUTE FUNCTION notify_event_inserted();
