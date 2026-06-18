// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Minimal, self-authored BPF compatibility shim.
//
// This provides just enough of the libbpf CO-RE conveniences (the SEC macro,
// the BTF-defined map field macros, and the handful of helper prototypes /
// byte-order builtins) for `egress.bpf.c` to compile to a valid BPF object with
// nothing more than `clang -target bpf` and a `vmlinux.h` generated from the
// running kernel's BTF.
//
// When the real libbpf headers are available (`<bpf/bpf_helpers.h>`), prefer
// them — they are the canonical, fully-featured definitions. This shim exists
// only so the deliverable is verifiable in minimal environments.

#ifndef REGORUS_BPF_COMPAT_H
#define REGORUS_BPF_COMPAT_H

#if __has_include(<bpf/bpf_helpers.h>)

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#else /* fall back to the self-contained shim */

#ifndef SEC
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

/* BTF-defined map field macros (same shape libbpf uses). */
#define __uint(name, val) int(*name)[val]
#define __type(name, val) typeof(val) *name
#define __array(name, val) typeof(val) *name[]

/* The few helpers this program calls, addressed by their stable helper IDs. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;

/* Byte-order conversion (network <-> host) for the BPF target. */
#if defined(__BYTE_ORDER__) && (__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#define bpf_htons(x) __builtin_bswap16(x)
#else
#define bpf_ntohl(x) (x)
#define bpf_ntohs(x) (x)
#define bpf_htonl(x) (x)
#define bpf_htons(x) (x)
#endif

#endif /* __has_include */

#endif /* REGORUS_BPF_COMPAT_H */
