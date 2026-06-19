// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Fixed, hand-audited lsm/file_open file-access enforcer.
//
// This is the kernel half of `regorus-bpf-lsm`. Like its egress sibling, it is
// intentionally a *fixed* program: policy is data, not code. The user-space
// exporter (`regorus_bpf_lsm::export`) compiles a `regorus-lift` EnforcerConfig
// into the rule table consumed here; this program merely scans that table.
//
// It is INTENDED to mirror the user-space reference enforcer
// `regorus_bpf_lsm::enforce`:
//
//   * extract the path and op from the opened `struct file`,
//   * scan up to MAX_RULES rule rows,
//   * ALLOW iff some rule's full conjunction matches (wildcards match
//     anything); otherwise the request is UNDECIDED, which collapses to DENY.
//
// For the LSM hook, the boundary verdicts map to return values:
//   ALLOW -> 0 (permit the open), DENY/UNDECIDED -> -EPERM (block).
//
// ---------------------------------------------------------------------------
// Phase-2 SOUNDNESS CAVEAT (documented, intentional).
//
// The kernel cannot trivially do arbitrary-length string matching, and
// `bpf_d_path` returns a path that is NOT the canonicalized string the policy
// was written against (no symlink/`..`/mount-namespace normalization), and is
// read into a BOUNDED buffer (MAX_PATH_PREFIX bytes). This program is therefore
// BEST-EFFORT:
//
//   * It compares only the first MAX_PATH_PREFIX bytes.
//   * EXACT matches additionally require the kernel path length to equal the
//     pattern length (so a bounded read cannot let a longer path masquerade as
//     a shorter exact pattern).
//   * A pattern longer than MAX_PATH_PREFIX is treated as a NON-match
//     (fail-closed), never a truncated/over-permissive match.
//
// Canonicalization stays in USER SPACE. The conformance reference for the
// lowered IR is the user-space enforcer (`src/enforcer.rs`), NOT this program.
//
// ---------------------------------------------------------------------------
// Kernel-version assumptions:
//   * BTF + CO-RE (a kernel with /sys/kernel/btf/vmlinux).
//   * BPF LSM support (CONFIG_BPF_LSM, `lsm.s`/`lsm` hooks) and the
//     `bpf_d_path` helper, both available on modern (>= 5.10) kernels.
// We cannot LOAD this here (uid 1000, no CAP_BPF); the gated compile test only
// checks that it COMPILES against the live BTF. If `struct file`/`struct path`
// are absent from BTF we still produce a compilable object via the guards below.

#include "vmlinux.h"
#include "regorus_bpf_compat.h"

#define MAX_RULES 64
// Must match regorus_bpf_lsm::abi::MAX_PATH_PREFIX.
#define MAX_PATH_PREFIX 256

// Path match kinds (must match regorus_bpf_lsm::plan::PathMatch ordering intent).
#define PATH_ANY 0
#define PATH_EXACT 1
#define PATH_PREFIX 2

// Op match kinds (must match regorus_bpf_lsm::plan::OpMatch).
#define OP_MATCH_ANY 0
#define OP_MATCH_EXACT 1

// File operations (must match regorus_bpf_lsm::abi::FileOp).
#define OP_READ 0
#define OP_WRITE 1
#define OP_EXEC 2

// Verdict ABI (must match regorus_bpf_lsm::abi::Verdict).
#define VERDICT_DENY 0
#define VERDICT_ALLOW 1
#define VERDICT_UNDECIDED 2

// FMODE_* bits from include/linux/fs.h (stable UAPI-adjacent constants).
#define FMODE_READ_BIT 0x1
#define FMODE_WRITE_BIT 0x2
#define FMODE_EXEC_BIT 0x20

#ifndef EPERM
#define EPERM 1
#endif

// One rule row: a full conjunction over the two observable fields. `pattern`
// holds the path bytes (exact or prefix), `pattern_len` its length in bytes
// (<= MAX_PATH_PREFIX; a longer pattern is rejected by user space before it
// reaches the kernel, and additionally guarded here).
struct file_rule {
	__u8 path_kind;  // PATH_ANY | PATH_EXACT | PATH_PREFIX
	__u8 op_kind;    // OP_MATCH_ANY | OP_MATCH_EXACT
	__u8 op_value;   // OP_READ | OP_WRITE | OP_EXEC
	__u8 _pad;
	__u32 pattern_len;
	char pattern[MAX_PATH_PREFIX];
};

// The rule table, populated by user space from the exported FilePlan.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_RULES);
	__type(key, __u32);
	__type(value, struct file_rule);
} file_rules SEC(".maps");

// Number of populated rule rows (index 0). A request matches only rows
// [0, rule_count); the rest of the fixed-size table is ignored.
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} file_rule_count SEC(".maps");

// A single-entry control map: when value != 0, enforcement is active. (When the
// table is empty / unconfigured this lets the loader choose fail-open during
// rollout; the default compiled-in behaviour is fail-closed.)
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} file_enabled SEC(".maps");

// A scratch percpu buffer to read the path into (the stack is too small for
// MAX_PATH_PREFIX).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[MAX_PATH_PREFIX]);
} file_path_scratch SEC(".maps");

// bpf_d_path (helper ID 147): copy a `struct path` into `buf`, returning the
// length (including NUL) on success or a negative errno. Declared here because
// the minimal compat shim only provides bpf_map_lookup_elem. When the real
// libbpf headers are present they declare it for us, so only add it in shim
// mode.
#if !__has_include(<bpf/bpf_helpers.h>)
static long (*bpf_d_path)(struct path *path, char *buf, __u32 sz) = (void *)147;
#endif

static __always_inline __u8 op_from_fmode(unsigned int f_mode)
{
	// Exec is the most restrictive intent; classify it first. Then write,
	// then default to read.
	if (f_mode & FMODE_EXEC_BIT)
		return OP_EXEC;
	if (f_mode & FMODE_WRITE_BIT)
		return OP_WRITE;
	return OP_READ;
}

// Bounded comparison of the first `n` bytes of `a` and `b`.
static __always_inline bool bytes_equal(const char *a, const char *b, __u32 n)
{
	for (__u32 i = 0; i < MAX_PATH_PREFIX; i++) {
		if (i >= n)
			break;
		if (a[i] != b[i])
			return false;
	}
	return true;
}

static __always_inline bool path_matches(const struct file_rule *r,
					  const char *path, __u32 path_len)
{
	__u32 plen = r->pattern_len;

	if (r->path_kind == PATH_ANY)
		return true;

	// A pattern we could not fully store cannot be verified soundly.
	if (plen == 0 || plen > MAX_PATH_PREFIX)
		return false;

	if (r->path_kind == PATH_EXACT) {
		// Exact requires equal length AND equal bytes; otherwise a longer
		// path sharing a prefix could masquerade as the exact pattern.
		if (path_len != plen)
			return false;
		return bytes_equal(path, r->pattern, plen);
	}

	if (r->path_kind == PATH_PREFIX) {
		// The path must be at least as long as the prefix and share it.
		if (path_len < plen)
			return false;
		return bytes_equal(path, r->pattern, plen);
	}

	return false;
}

static __always_inline bool op_matches(const struct file_rule *r, __u8 op)
{
	if (r->op_kind == OP_MATCH_ANY)
		return true;
	return r->op_kind == OP_MATCH_EXACT && op == r->op_value;
}

SEC("lsm/file_open")
int regorus_file_open(unsigned long long *ctx)
{
	// LSM/BTF programs receive a pointer to an array of u64 arguments. For
	// `file_open(struct file *file)` the file pointer is ctx[0]. (This is the
	// manual equivalent of libbpf's BPF_PROG() unwrapping, which the minimal
	// compat shim does not provide.)
	struct file *file = (struct file *)ctx[0];

	__u32 zero = 0;

	__u32 *enabled = bpf_map_lookup_elem(&file_enabled, &zero);
	if (enabled && *enabled == 0) {
		// Enforcement disabled: allow (fail-open is an explicit opt-in).
		return 0;
	}

	char *buf = bpf_map_lookup_elem(&file_path_scratch, &zero);
	if (!buf)
		return -EPERM; // no scratch -> cannot evaluate -> fail closed

	// Best-effort: read a bounded, NON-canonical path string. Direct field
	// access (`&file->f_path`) is CO-RE-relocated by clang against the BTF.
	long ret = bpf_d_path(&file->f_path, buf, MAX_PATH_PREFIX);
	if (ret <= 0)
		return -EPERM; // could not extract the path -> fail closed

	// `ret` includes the trailing NUL; the byte length is ret - 1.
	__u32 path_len = (__u32)ret;
	if (path_len > 0)
		path_len -= 1;
	if (path_len > MAX_PATH_PREFIX)
		path_len = MAX_PATH_PREFIX;

	__u8 op = op_from_fmode(file->f_mode);

	__u32 *count_p = bpf_map_lookup_elem(&file_rule_count, &zero);
	__u32 count = count_p ? *count_p : 0;
	if (count > MAX_RULES)
		count = MAX_RULES;

	int verdict = VERDICT_UNDECIDED;

	for (__u32 i = 0; i < MAX_RULES; i++) {
		if (i >= count)
			break;
		struct file_rule *r = bpf_map_lookup_elem(&file_rules, &i);
		if (!r)
			continue;
		if (path_matches(r, buf, path_len) && op_matches(r, op)) {
			verdict = VERDICT_ALLOW;
			break;
		}
	}

	// Boundary collapse: only ALLOW returns 0 (permit); UNDECIDED/DENY map to
	// -EPERM (block the open).
	return verdict == VERDICT_ALLOW ? 0 : -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
