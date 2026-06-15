CREATE TABLE IF NOT EXISTS v2_entries (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	listen TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	enabled INTEGER NOT NULL DEFAULT 1,
	sniff INTEGER NOT NULL DEFAULT 0,
	auth_json TEXT NOT NULL DEFAULT '{}',
	protocol_config_json TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_subscriptions (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	url TEXT NOT NULL,
	type TEXT NOT NULL DEFAULT 'auto',
	enabled INTEGER NOT NULL DEFAULT 1,
	refresh_interval INTEGER NOT NULL DEFAULT 3600,
	last_update_at TEXT NOT NULL DEFAULT '',
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_nodes (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL,
	region TEXT NOT NULL DEFAULT '',
	provider TEXT NOT NULL DEFAULT '',
	address TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	enabled INTEGER NOT NULL DEFAULT 1,
	alive INTEGER NOT NULL DEFAULT 0,
	latency INTEGER NOT NULL DEFAULT 0,
	source TEXT NOT NULL DEFAULT '',
	subscription_id TEXT NOT NULL DEFAULT '',
	manual_group_ids_json TEXT NOT NULL DEFAULT '[]',
	tags_json TEXT NOT NULL DEFAULT '[]',
	raw_config_json TEXT NOT NULL DEFAULT '{}',
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_region_groups (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	mode TEXT NOT NULL DEFAULT 'smart',
	selected_node_id TEXT NOT NULL DEFAULT '',
	smart_json TEXT NOT NULL DEFAULT '{}',
	node_ids_json TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_app_policy_groups (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	type TEXT NOT NULL DEFAULT 'selector',
	selected TEXT NOT NULL DEFAULT '',
	candidates_json TEXT NOT NULL DEFAULT '[]',
	enabled INTEGER NOT NULL DEFAULT 1,
	sort_order INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_route_rules (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	match_type TEXT NOT NULL DEFAULT 'rule_set',
	match_value TEXT NOT NULL DEFAULT '',
	inbound TEXT NOT NULL DEFAULT '',
	rule_set TEXT NOT NULL DEFAULT '',
	outbound TEXT NOT NULL,
	enabled INTEGER NOT NULL DEFAULT 1,
	rule_order INTEGER NOT NULL DEFAULT 0,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS v2_rule_sets (
	tag TEXT PRIMARY KEY,
	type TEXT NOT NULL DEFAULT 'inline',
	format TEXT NOT NULL DEFAULT '',
	path TEXT NOT NULL DEFAULT '',
	url TEXT NOT NULL DEFAULT '',
	update_interval TEXT NOT NULL DEFAULT '',
	download_detour TEXT NOT NULL DEFAULT '',
	domain_json TEXT NOT NULL DEFAULT '[]',
	domain_suffix_json TEXT NOT NULL DEFAULT '[]',
	domain_keyword_json TEXT NOT NULL DEFAULT '[]',
	ip_cidr_json TEXT NOT NULL DEFAULT '[]',
	updated_at TEXT NOT NULL
);
