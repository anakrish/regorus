package network_segmentation

# ============================================================
# Network Segmentation Compliance — v2
# ============================================================
#
# v2: Maximally restructured — same DMZ→internal-DB semantics;
#     PII-over-unencrypted rule DROPPED (more permissive).
#
# Structural differences from v1:
#   1. `every` quantifier         replaces   violation partial-set + count==0
#   2. Object-comprehension maps  replaces   linear `some X in` scans
#   3. Function rules             replaces   inline multi-way joins
#   4. Connection-centric logic   replaces   service-centric iteration
#   5. No partial sets at all     replaces   two partial sets + helper
#   6. `compliant if`             replaces   `compliant := true if`
#   7. PII rule dropped           → more permissive than v1
# ============================================================

default compliant := false

# ---------------------------------------------------------------
# Lookup maps — object comprehensions keyed by unique identifier
# ---------------------------------------------------------------
# These replace the linear scans used in v1.  Accessing a
# non-existent key simply makes the function undefined, which
# is safe — the caller rule fails gracefully.

zone_of[svc.name] := svc.zone_id if {
    some svc in input.services
}

zone_is_dmz[z.id] := z.dmz if {
    some z in input.zones
}

db_is_internal[d.name] := d.internal if {
    some d in input.databases
}

# ---------------------------------------------------------------
# Function: is a service in the DMZ?
# ---------------------------------------------------------------
in_dmz(svc_name) if {
    zone_id := zone_of[svc_name]
    zone_is_dmz[zone_id] == true
}

# ---------------------------------------------------------------
# Function: does a connection target an internal database?
# ---------------------------------------------------------------
targets_internal_db(conn) if {
    db_is_internal[conn.target] == true
}

# ---------------------------------------------------------------
# Function: is a connection a DMZ → internal-DB violation?
# ---------------------------------------------------------------
dmz_to_internal(conn) if {
    in_dmz(conn.source)
    targets_internal_db(conn)
}

# ---------------------------------------------------------------
# Top-level decision — universal quantifier over connections
# ---------------------------------------------------------------
# Instead of collecting violations into a set and checking
# count == 0, v2 uses `every` to assert that NO connection
# is a DMZ→internal-DB violation.

compliant if {
    every conn in input.connections {
        not dmz_to_internal(conn)
    }
}
