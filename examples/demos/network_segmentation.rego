package network_segmentation

# ============================================================
# Network Segmentation Compliance
# ============================================================
#
# Scenario
# --------
# A security team reviews a microservice network topology before
# deployment.  The input describes four collections:
#
#   input.services[]      – microservices
#       .name             – unique identifier (string)
#       .zone_id          – the network zone it resides in (string FK)
#       .handles_pii      – whether it processes personal data (bool)
#
#   input.zones[]         – network zones
#       .id               – unique identifier (string)
#       .dmz              – whether the zone is a DMZ (bool)
#
#   input.connections[]   – directed network links between services
#       .source           – originating service name (string FK)
#       .target           – destination service/database name (string FK)
#       .encrypted        – whether the link uses TLS (bool)
#
#   input.databases[]     – data stores
#       .name             – unique identifier (string)
#       .internal         – whether the DB is on the internal network (bool)
#
# Policy
# ------
# The topology is COMPLIANT only when ZERO violations exist.
#
# Violation sources:
#   1. A service in the DMZ connects to an internal database.
#   2. A service that handles PII uses an unencrypted connection.
#
# Why this is interesting for Z3
# ------------------------------
# Rule 1 is a **4-way cross-collection join**: services → zones
# (to determine DMZ membership), services → connections (to find
# outbound links), and connections → databases (to check the
# target).  Z3 must simultaneously satisfy string equalities
# across four different arrays to synthesise a counterexample.
#
# Rule 2 is a 2-way join (services → connections) with mixed
# Boolean and string constraints.
#
# The `--cover-line` / `--avoid-line` flags let you ask Z3 to
# produce a violation through ONE specific rule while proving
# the other rule's path is never taken — a form of targeted
# counterexample generation.
# ============================================================

# ---------------------------------------------------------------
# Top-level decision
# ---------------------------------------------------------------

# Default: unless the body below fires, the topology is non-compliant.
# (Fail-closed: an empty or malformed input is treated as non-compliant.)
default compliant := false

# `compliant` becomes true exactly when the violation set is empty.
# `count(violation)` triggers evaluation of both partial-set rules
# below.  The symbolic engine models the result as a cardinality
# constraint over a SymbolicSet.
compliant := true if {
    count(violation) == 0
}

# ---------------------------------------------------------------
# Violation Rule 1 — DMZ Service → Internal Database
# ---------------------------------------------------------------
# A service located in the DMZ must never connect directly to an
# internal database.  This prevents an Internet-facing service
# from having a direct path to sensitive backend data.
#
# Symbolically this is a 4-way join.  Z3 must find values for:
#
#   ∃ svc  ∈ dmz_service,           (resolved via helper rule)
#   ∃ conn ∈ input.connections,
#   ∃ db   ∈ input.databases:
#       conn.source == svc.name     (string eq: link originates at svc)
#     ∧ db.name    == conn.target   (string eq: link targets the DB)
#     ∧ db.internal == true         (boolean: DB is on internal network)
#
# The `dmz_service` helper (below) adds another join level:
#   ∃ zone ∈ input.zones:
#       zone.id  == svc.zone_id ∧ zone.dmz == true
#
# That makes it effectively a 4-collection coordination problem.
# ---------------------------------------------------------------
violation contains svc.name if {
    some svc in dmz_service            # draw from the DMZ helper set
    some conn in input.connections     # iterate over network links
    conn.source == svc.name            # JOIN: connection ↔ service
    some db in input.databases         # iterate over databases
    db.name == conn.target             # JOIN: database ↔ connection target
    db.internal == true                # constraint: DB is internal
}

# ---------------------------------------------------------------
# Violation Rule 2 — PII Over Unencrypted Connection
# ---------------------------------------------------------------
# A service that handles personally identifiable information (PII)
# must only communicate over encrypted (TLS) links.  An
# unencrypted connection from a PII-handling service is a
# violation.
#
# Symbolically this is a 2-way join:
#
#   ∃ svc  ∈ input.services,
#   ∃ conn ∈ input.connections:
#       svc.handles_pii == true        (boolean)
#     ∧ conn.source     == svc.name    (string equality)
#     ∧ conn.encrypted  == false       (boolean)
#
# Simpler than Rule 1, but still requires Z3 to coordinate a
# string equality between two different arrays.
# ---------------------------------------------------------------
violation contains svc.name if {
    some svc in input.services         # iterate over all services
    svc.handles_pii == true            # constraint: service handles PII
    some conn in input.connections     # iterate over network links
    conn.source == svc.name            # JOIN: connection ↔ service
    conn.encrypted == false            # constraint: link is unencrypted
}

# ---------------------------------------------------------------
# Helper Rule — DMZ Service Detection
# ---------------------------------------------------------------
# A service is classified as a DMZ service when it resides in a
# network zone whose `dmz` flag is true.
#
# This is a 2-way join (services → zones on zone_id == id) that
# feeds into Violation Rule 1.  The entire service object is
# added to the set so that Rule 1 can access `.name` on it.
#
# Symbolically:
#   ∃ svc  ∈ input.services,
#   ∃ zone ∈ input.zones:
#       zone.id  == svc.zone_id   (string equality)
#     ∧ zone.dmz == true          (boolean)
# ---------------------------------------------------------------
dmz_service contains svc if {
    some svc in input.services         # iterate over services
    some zone in input.zones           # iterate over zones
    zone.id == svc.zone_id            # JOIN: zone ↔ service
    zone.dmz == true                   # constraint: zone is a DMZ
}
