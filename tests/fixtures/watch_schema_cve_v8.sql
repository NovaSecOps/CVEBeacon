-- Schema 8 with sparse provider/search storage, before Teams bot storage.
CREATE TABLE IF NOT EXISTS watch_origin (
        cve_id TEXT PRIMARY KEY, source TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_euvd_override (
        cve_id TEXT PRIMARY KEY, items_json TEXT NOT NULL, checked_at TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_cve_list_queue (
        cve_id TEXT PRIMARY KEY, fetch_time TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_initial_cve (
        cve_id TEXT PRIMARY KEY, source TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_source_check (
        cve_id TEXT NOT NULL, source TEXT NOT NULL, present INTEGER,
        checked_at TEXT NOT NULL, error TEXT,
        PRIMARY KEY(cve_id,source)
    );
CREATE TABLE IF NOT EXISTS watch_provider (
        cve_id TEXT NOT NULL, source TEXT NOT NULL,
        record_json TEXT NOT NULL, payload_json TEXT NOT NULL,
        source_updated TEXT, checked_at TEXT NOT NULL,
        PRIMARY KEY(cve_id,source)
    );
CREATE TABLE IF NOT EXISTS watch_search (
        cve_id TEXT NOT NULL, source TEXT NOT NULL, text TEXT NOT NULL,
        PRIMARY KEY(cve_id,source)
    );
CREATE TABLE IF NOT EXISTS watch_meta (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_cve (
        cve_id TEXT PRIMARY KEY,
        published TEXT,
        last_modified TEXT,
        status TEXT NOT NULL CHECK(status IN ('published','rejected','reserved')),
        description TEXT,
        source_identifier TEXT,
        cvss_json TEXT NOT NULL,
        cwes_json TEXT NOT NULL,
        products_json TEXT NOT NULL,
        references_json TEXT NOT NULL,
        ssvc_exploitation TEXT CHECK(ssvc_exploitation IN ('none','poc','active') OR ssvc_exploitation IS NULL),
        cisa_kev_added TEXT,
        cisa_kev_due TEXT,
        cisa_required_action TEXT,
        cisa_ransomware TEXT,
        first_seen TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
CREATE INDEX IF NOT EXISTS watch_cve_ssvc ON watch_cve(ssvc_exploitation);
CREATE TABLE IF NOT EXISTS watch_euvd_item (
        euvd_id TEXT PRIMARY KEY,
        cve_ids_json TEXT NOT NULL,
        date_updated TEXT,
        score REAL,
        version TEXT,
        vector TEXT,
        exploited_since TEXT,
        vendors_json TEXT NOT NULL,
        seen_at TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_euvd_alias (
        cve_id TEXT NOT NULL,
        euvd_id TEXT NOT NULL,
        PRIMARY KEY(cve_id, euvd_id),
        FOREIGN KEY(euvd_id) REFERENCES watch_euvd_item(euvd_id) ON DELETE CASCADE
    );
CREATE INDEX IF NOT EXISTS watch_euvd_alias_euvd ON watch_euvd_alias(euvd_id);
CREATE TABLE IF NOT EXISTS watch_euvd_scan (
        euvd_id TEXT PRIMARY KEY,
        page INTEGER NOT NULL
    );
CREATE INDEX IF NOT EXISTS watch_euvd_scan_page ON watch_euvd_scan(page);
CREATE TABLE IF NOT EXISTS watch_kev (
        catalog TEXT NOT NULL CHECK(catalog IN ('cisa','eu')),
        cve_id TEXT NOT NULL,
        date_added TEXT,
        due_date TEXT,
        required_action TEXT,
        ransomware TEXT,
        PRIMARY KEY(catalog, cve_id)
    );
CREATE INDEX IF NOT EXISTS watch_kev_cve ON watch_kev(cve_id);
CREATE TABLE IF NOT EXISTS watch_epss (
        cve_id TEXT PRIMARY KEY,
        epss REAL NOT NULL,
        percentile REAL NOT NULL,
        score_date TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_view (
        cve_id TEXT PRIMARY KEY,
        fingerprint TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_touched (
        cve_id TEXT PRIMARY KEY,
        touched_at TEXT NOT NULL
    );
CREATE TABLE IF NOT EXISTS watch_lookup (
        cve_id TEXT PRIMARY KEY,
        attempts INTEGER NOT NULL DEFAULT 0,
        next_attempt_at TEXT NOT NULL,
        last_error TEXT
    );
CREATE INDEX IF NOT EXISTS watch_lookup_due ON watch_lookup(next_attempt_at);
CREATE TABLE IF NOT EXISTS watch_alert_state (
        rule TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        first_matched_at TEXT NOT NULL,
        snapshot_json TEXT NOT NULL,
        rule_hash TEXT NOT NULL,
        providers_hash TEXT NOT NULL,
        PRIMARY KEY(rule, cve_id)
    );
CREATE TABLE IF NOT EXISTS watch_event (
        id INTEGER PRIMARY KEY,
        rule TEXT NOT NULL,
        cve_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        reasons_json TEXT NOT NULL,
        details_json TEXT NOT NULL DEFAULT '{}',
        occurrence TEXT NOT NULL,
        initial INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(rule, cve_id, kind, occurrence)
    );
CREATE TABLE IF NOT EXISTS watch_delivery (
        event_id INTEGER NOT NULL,
        channel TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','sending','sent','failed','ambiguous')),
        attempts INTEGER NOT NULL DEFAULT 0,
        last_error TEXT,
        first_attempt_at TEXT,
        updated_at TEXT NOT NULL,
        PRIMARY KEY(event_id, channel)
    );
CREATE TABLE IF NOT EXISTS watch_report (
        id INTEGER PRIMARY KEY,
        cve_id TEXT NOT NULL,
        action TEXT NOT NULL CHECK(action IN ('report','unreport')),
        by TEXT NOT NULL,
        user_id INTEGER,
        username TEXT,
        identity_mode TEXT CHECK(identity_mode IN ('open','registered','authenticated') OR identity_mode IS NULL),
        os_account TEXT,
        host TEXT,
        note TEXT,
        at TEXT NOT NULL,
        chain TEXT,
        chain_version INTEGER NOT NULL DEFAULT 1 CHECK(chain_version IN (0,1))
    );
CREATE INDEX IF NOT EXISTS watch_event_created ON watch_event(created_at, id);
CREATE INDEX IF NOT EXISTS watch_delivery_status ON watch_delivery(status);
CREATE INDEX IF NOT EXISTS watch_report_cve ON watch_report(cve_id, id);
INSERT INTO watch_meta VALUES ('schema_version','8');
INSERT INTO watch_meta VALUES ('provider_storage','sparse-v1');
INSERT INTO watch_meta VALUES ('report_legacy_max_id','0');
