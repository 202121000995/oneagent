package repository

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"nodetoolsagent/internal/model"
)

const V2SchemaSQL = `
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
`

type V2Repository struct {
	db *sql.DB
}

func NewV2Repository(db *sql.DB) *V2Repository {
	return &V2Repository{db: db}
}

func (r *V2Repository) Migrate(ctx context.Context) error {
	_, err := r.db.ExecContext(ctx, V2SchemaSQL)
	return err
}

func (r *V2Repository) SaveModel(ctx context.Context, m model.V2Model) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, table := range []string{
		"v2_entries",
		"v2_subscriptions",
		"v2_nodes",
		"v2_region_groups",
		"v2_app_policy_groups",
		"v2_route_rules",
		"v2_rule_sets",
	} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return err
		}
	}

	now := time.Now().Format(time.RFC3339)
	for _, entry := range m.Entries {
		if entry.ID == "" {
			return fmt.Errorf("entry id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_entries (id, name, type, listen, port, enabled, sniff, auth_json, protocol_config_json, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.ID, entry.Name, entry.Type, entry.Listen, entry.Port, boolInt(entry.Enabled), boolInt(entry.Sniff),
			mustJSON(entry.Auth), mustJSON(entry.ProtocolConfig), now,
		); err != nil {
			return err
		}
	}
	for _, sub := range m.Subscriptions {
		if sub.ID == "" {
			return fmt.Errorf("subscription id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_subscriptions (id, name, url, type, enabled, refresh_interval, last_update_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			sub.ID, sub.Name, sub.URL, sub.Type, boolInt(sub.Enabled), sub.RefreshInterval, sub.LastUpdateAt, now,
		); err != nil {
			return err
		}
	}
	for _, node := range m.Nodes {
		if node.ID == "" {
			return fmt.Errorf("node id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_nodes (id, name, type, region, provider, address, port, enabled, alive, latency, source, subscription_id,
			 manual_group_ids_json, tags_json, raw_config_json, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			node.ID, node.Name, node.Type, node.Region, node.Provider, node.Address, node.Port, boolInt(node.Enabled),
			boolInt(node.Alive), node.Latency, node.Source, node.SubscriptionID, mustJSON(node.ManualGroupIDs),
			mustJSON(node.Tags), mustJSON(node.RawConfig), now,
		); err != nil {
			return err
		}
	}
	for _, group := range m.RegionGroups {
		if group.ID == "" {
			return fmt.Errorf("region group id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_region_groups (id, name, mode, selected_node_id, smart_json, node_ids_json, enabled, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			group.ID, group.Name, group.Mode, group.SelectedNodeID, mustJSON(group.Smart), mustJSON(group.NodeIDs), boolInt(group.Enabled), now,
		); err != nil {
			return err
		}
	}
	for _, policy := range m.AppPolicyGroups {
		if policy.ID == "" {
			return fmt.Errorf("app policy group id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_app_policy_groups (id, name, type, selected, candidates_json, enabled, sort_order, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			policy.ID, policy.Name, policy.Type, policy.Selected, mustJSON(policy.Candidates), boolInt(policy.Enabled), policy.SortOrder, now,
		); err != nil {
			return err
		}
	}
	for _, rule := range m.RouteRules {
		if rule.ID == "" {
			return fmt.Errorf("route rule id is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_route_rules (id, name, match_type, match_value, inbound, rule_set, outbound, enabled, rule_order, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rule.ID, rule.Name, rule.MatchType, rule.MatchValue, rule.Inbound, rule.RuleSet, rule.Outbound, boolInt(rule.Enabled), rule.Order, now,
		); err != nil {
			return err
		}
	}
	for _, rs := range m.RuleSets {
		if rs.Tag == "" {
			return fmt.Errorf("rule set tag is required")
		}
		if _, err := tx.ExecContext(ctx,
			`INSERT INTO v2_rule_sets (tag, type, format, path, url, update_interval, download_detour,
			 domain_json, domain_suffix_json, domain_keyword_json, ip_cidr_json, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rs.Tag, rs.Type, rs.Format, rs.Path, rs.URL, rs.UpdateInterval, rs.DownloadDetour,
			mustJSON(rs.Domain), mustJSON(rs.DomainSuffix), mustJSON(rs.DomainKeyword), mustJSON(rs.IPCIDR), now,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (r *V2Repository) LoadModel(ctx context.Context) (model.V2Model, bool, error) {
	var m model.V2Model

	rows, err := r.db.QueryContext(ctx, `SELECT id, name, type, listen, port, enabled, sniff, auth_json, protocol_config_json FROM v2_entries ORDER BY name`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var entry model.EntryConfig
		var authJSON, protocolJSON string
		var enabled, sniff int
		if err := rows.Scan(&entry.ID, &entry.Name, &entry.Type, &entry.Listen, &entry.Port, &enabled, &sniff, &authJSON, &protocolJSON); err != nil {
			rows.Close()
			return m, false, err
		}
		entry.Enabled = enabled != 0
		entry.Sniff = sniff != 0
		if err := decodeJSON(authJSON, &entry.Auth); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(protocolJSON, &entry.ProtocolConfig); err != nil {
			rows.Close()
			return m, false, err
		}
		m.Entries = append(m.Entries, entry)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT id, name, url, type, enabled, refresh_interval, last_update_at FROM v2_subscriptions ORDER BY name`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var sub model.SubscriptionConfig
		var enabled int
		if err := rows.Scan(&sub.ID, &sub.Name, &sub.URL, &sub.Type, &enabled, &sub.RefreshInterval, &sub.LastUpdateAt); err != nil {
			rows.Close()
			return m, false, err
		}
		sub.Enabled = enabled != 0
		m.Subscriptions = append(m.Subscriptions, sub)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT id, name, type, region, provider, address, port, enabled, alive, latency, source, subscription_id,
		manual_group_ids_json, tags_json, raw_config_json FROM v2_nodes ORDER BY name`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var node model.OutboundNodeConfig
		var enabled, alive int
		var manualJSON, tagsJSON, rawJSON string
		if err := rows.Scan(&node.ID, &node.Name, &node.Type, &node.Region, &node.Provider, &node.Address, &node.Port,
			&enabled, &alive, &node.Latency, &node.Source, &node.SubscriptionID, &manualJSON, &tagsJSON, &rawJSON); err != nil {
			rows.Close()
			return m, false, err
		}
		node.Enabled = enabled != 0
		node.Alive = alive != 0
		if err := decodeJSON(manualJSON, &node.ManualGroupIDs); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(tagsJSON, &node.Tags); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(rawJSON, &node.RawConfig); err != nil {
			rows.Close()
			return m, false, err
		}
		m.Nodes = append(m.Nodes, node)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT id, name, mode, selected_node_id, smart_json, node_ids_json, enabled FROM v2_region_groups ORDER BY id`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var group model.RegionGroupConfig
		var enabled int
		var smartJSON, nodeIDsJSON string
		if err := rows.Scan(&group.ID, &group.Name, &group.Mode, &group.SelectedNodeID, &smartJSON, &nodeIDsJSON, &enabled); err != nil {
			rows.Close()
			return m, false, err
		}
		group.Enabled = enabled != 0
		if err := decodeJSON(smartJSON, &group.Smart); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(nodeIDsJSON, &group.NodeIDs); err != nil {
			rows.Close()
			return m, false, err
		}
		m.RegionGroups = append(m.RegionGroups, group)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT id, name, type, selected, candidates_json, enabled, sort_order FROM v2_app_policy_groups ORDER BY sort_order, id`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var policy model.AppPolicyGroupConfig
		var enabled int
		var candidatesJSON string
		if err := rows.Scan(&policy.ID, &policy.Name, &policy.Type, &policy.Selected, &candidatesJSON, &enabled, &policy.SortOrder); err != nil {
			rows.Close()
			return m, false, err
		}
		policy.Enabled = enabled != 0
		if err := decodeJSON(candidatesJSON, &policy.Candidates); err != nil {
			rows.Close()
			return m, false, err
		}
		m.AppPolicyGroups = append(m.AppPolicyGroups, policy)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT id, name, match_type, match_value, inbound, rule_set, outbound, enabled, rule_order FROM v2_route_rules ORDER BY rule_order, id`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var rule model.RouteRuleConfig
		var enabled int
		if err := rows.Scan(&rule.ID, &rule.Name, &rule.MatchType, &rule.MatchValue, &rule.Inbound, &rule.RuleSet, &rule.Outbound, &enabled, &rule.Order); err != nil {
			rows.Close()
			return m, false, err
		}
		rule.Enabled = enabled != 0
		m.RouteRules = append(m.RouteRules, rule)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	rows, err = r.db.QueryContext(ctx, `SELECT tag, type, format, path, url, update_interval, download_detour,
		domain_json, domain_suffix_json, domain_keyword_json, ip_cidr_json FROM v2_rule_sets ORDER BY tag`)
	if err != nil {
		return m, false, err
	}
	for rows.Next() {
		var rs model.RuleSetConfig
		var domainJSON, suffixJSON, keywordJSON, ipJSON string
		if err := rows.Scan(&rs.Tag, &rs.Type, &rs.Format, &rs.Path, &rs.URL, &rs.UpdateInterval, &rs.DownloadDetour,
			&domainJSON, &suffixJSON, &keywordJSON, &ipJSON); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(domainJSON, &rs.Domain); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(suffixJSON, &rs.DomainSuffix); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(keywordJSON, &rs.DomainKeyword); err != nil {
			rows.Close()
			return m, false, err
		}
		if err := decodeJSON(ipJSON, &rs.IPCIDR); err != nil {
			rows.Close()
			return m, false, err
		}
		m.RuleSets = append(m.RuleSets, rs)
	}
	if err := rows.Close(); err != nil {
		return m, false, err
	}

	return m, hasAnyV2Data(m), nil
}

func boolInt(value bool) int {
	if value {
		return 1
	}
	return 0
}

func mustJSON(value any) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "null"
	}
	return string(data)
}

func decodeJSON(raw string, target any) error {
	if raw == "" {
		raw = "null"
	}
	return json.Unmarshal([]byte(raw), target)
}

func hasAnyV2Data(m model.V2Model) bool {
	return len(m.Entries) > 0 ||
		len(m.Subscriptions) > 0 ||
		len(m.Nodes) > 0 ||
		len(m.RegionGroups) > 0 ||
		len(m.AppPolicyGroups) > 0 ||
		len(m.RouteRules) > 0 ||
		len(m.RuleSets) > 0
}
