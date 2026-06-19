// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Fixed, hand-audited cgroup/connect4 egress enforcer.
//
// This is the kernel half of `regorus-bpf`. It is intentionally a *fixed*
// program: policy is data, not code. The user-space exporter
// (`regorus_bpf::export`) compiles a `regorus-lift` EnforcerConfig into the
// clause table consumed here; this program merely scans that table.
//
// It mirrors, byte-for-byte, the behaviour of the user-space reference enforcer
// `regorus_bpf::enforce`:
//
//   * extract dest_ip / dest_port / proto from the connect4 context,
//   * scan up to MAX_CLAUSES clause rows,
//   * ALLOW iff some clause's full conjunction matches (wildcards match
//     anything); otherwise the request is UNDECIDED, which collapses to DENY.
//
// Map values are stored in HOST byte order (matching the Rust side); the
// context fields, which the kernel presents in network byte order, are
// converted with bpf_ntohl / bpf_ntohs before comparison.

#include "vmlinux.h"
#include "regorus_bpf_compat.h"

#define MAX_CLAUSES 64

// IP match kinds (must match regorus_bpf::plan::IpMatch ordering intent).
#define IP_ANY 0
#define IP_EXACT 1
#define IP_CIDR 2

// Scalar match kinds (must match regorus_bpf::plan::ScalarMatch).
#define MATCH_ANY 0
#define MATCH_EXACT 1
#define MATCH_RANGE 2

// Verdict ABI (must match regorus_bpf::abi::Verdict). UNDECIDED collapses to
// DENY at the boundary, which for cgroup/connect4 means "return 0" (block).
#define VERDICT_DENY 0
#define VERDICT_ALLOW 1
#define VERDICT_UNDECIDED 2

// One clause row: a full conjunction over the three observable fields. All
// integer values are HOST byte order.
//
// The `port_kind` selects how the port is matched (mirrors
// regorus_bpf::plan::ScalarMatch<u16>):
//   * MATCH_ANY   -> wildcard (port ignored),
//   * MATCH_EXACT -> port == port_value,
//   * MATCH_RANGE -> port_min <= port <= port_max (inclusive). A range always
//                    requires a present port, matching the Rust enforcer.
struct clause_entry {
	__u8 ip_kind;     // IP_ANY | IP_EXACT | IP_CIDR
	__u8 prefix_len;  // valid when ip_kind == IP_CIDR (0..=32)
	__u8 port_kind;   // MATCH_ANY | MATCH_EXACT | MATCH_RANGE
	__u8 proto_kind;  // MATCH_ANY | MATCH_EXACT
	__u32 ip_value;   // exact address or CIDR network (host order)
	__u16 port_value; // exact port (host order), valid when MATCH_EXACT
	__u16 port_min;   // inclusive low bound, valid when MATCH_RANGE
	__u16 port_max;   // inclusive high bound, valid when MATCH_RANGE
	__u8 proto_value; // exact IPPROTO_*
	__u8 _pad;
};

// The clause table, populated by user space from the exported MapPlan.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CLAUSES);
	__type(key, __u32);
	__type(value, struct clause_entry);
} egress_clauses SEC(".maps");

// Number of populated clause rows (index 0). A request matches only rows
// [0, clause_count); the rest of the fixed-size table is ignored.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} egress_clause_count SEC(".maps");

// A single-entry control map: when value != 0, enforcement is active. (When the
// table is empty / unconfigured this lets the loader choose fail-open during
// rollout; the default compiled-in behaviour is fail-closed.)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} egress_enabled SEC(".maps");

static __always_inline bool ip_matches(const struct clause_entry *c, __u32 addr)
{
	if (c->ip_kind == IP_ANY)
		return true;
	if (c->ip_kind == IP_EXACT)
		return addr == c->ip_value;
	if (c->ip_kind == IP_CIDR) {
		__u8 plen = c->prefix_len;
		if (plen == 0)
			return true;
		if (plen > 32)
			return false;
		__u32 mask = 0xffffffffu << (32 - plen);
		return (addr & mask) == (c->ip_value & mask);
	}
	return false;
}

static __always_inline bool port_matches(const struct clause_entry *c, __u16 port)
{
	if (c->port_kind == MATCH_ANY)
		return true;
	if (c->port_kind == MATCH_EXACT)
		return port == c->port_value;
	if (c->port_kind == MATCH_RANGE)
		return port >= c->port_min && port <= c->port_max;
	return false;
}

static __always_inline bool proto_matches(const struct clause_entry *c, __u8 proto)
{
	if (c->proto_kind == MATCH_ANY)
		return true;
	return c->proto_kind == MATCH_EXACT && proto == c->proto_value;
}

SEC("cgroup/connect4")
int regorus_egress_connect4(struct bpf_sock_addr *ctx)
{
	__u32 zero = 0;

	__u32 *enabled = bpf_map_lookup_elem(&egress_enabled, &zero);
	if (enabled && *enabled == 0) {
		// Enforcement disabled: allow (fail-open is an explicit opt-in).
		return 1;
	}

	// Extract the observable fields. Context fields are network byte order.
	__u32 dest_ip = bpf_ntohl(ctx->user_ip4);
	__u16 dest_port = bpf_ntohs(ctx->user_port);
	__u8 proto = (__u8)ctx->protocol;

	__u32 *count_p = bpf_map_lookup_elem(&egress_clause_count, &zero);
	__u32 count = count_p ? *count_p : 0;
	if (count > MAX_CLAUSES)
		count = MAX_CLAUSES;

	int verdict = VERDICT_UNDECIDED;

	for (__u32 i = 0; i < MAX_CLAUSES; i++) {
		if (i >= count)
			break;
		struct clause_entry *c = bpf_map_lookup_elem(&egress_clauses, &i);
		if (!c)
			continue;
		if (ip_matches(c, dest_ip) && port_matches(c, dest_port) &&
		    proto_matches(c, proto)) {
			verdict = VERDICT_ALLOW;
			break;
		}
	}

	// Boundary collapse: only ALLOW returns 1; UNDECIDED/DENY -> 0 (block).
	return verdict == VERDICT_ALLOW ? 1 : 0;
}

char LICENSE[] SEC("license") = "GPL";
