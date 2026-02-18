package container_admission

# ============================================================
# Container Admission Controller
# ============================================================
#
# Scenario
# --------
# An orchestrator (e.g. Kubernetes) asks: "May I admit this set
# of containers?"  The input describes three collections:
#
#   input.containers[]   – workloads to be scheduled
#       .name            – unique identifier (string)
#       .privileged      – whether the container runs as root (bool)
#       .host_id         – the host it is scheduled on (string FK)
#       .volume_ids[]    – volumes it mounts (array of string FKs)
#
#   input.hosts[]        – available cluster nodes
#       .id              – unique identifier (string)
#       .public          – whether the node is Internet-facing (bool)
#
#   input.volumes[]      – storage volumes
#       .id              – unique identifier (string)
#       .encrypted       – whether data-at-rest is encrypted (bool)
#
# Policy
# ------
# The deployment is ALLOWED only when ZERO violations exist.
#
# Violation sources:
#   1. Any container that runs in privileged mode.
#   2. Any "sensitive" container (mounts an unencrypted volume)
#      that is scheduled on a public host.
#
# Why this is interesting for Z3
# ------------------------------
# Rule 2 is a 3-way cross-collection join: to trigger it Z3 must
# find string IDs that link containers → volumes (via volume_ids)
# AND containers → hosts (via host_id), while simultaneously
# satisfying Boolean and equality constraints across all three
# collections.  Schema constraints (x-unique, minItems, etc.)
# further restrict the search space.
# ============================================================

# ---------------------------------------------------------------
# Top-level decision
# ---------------------------------------------------------------

# Default: unless the body below evaluates to true, deny.
default allow := false

# `allow` becomes true exactly when the violation set is empty.
# `count(violation)` evaluates the partial-set rules below and
# returns the number of distinct elements.  The symbolic engine
# models this as a cardinality constraint over a SymbolicSet.
allow := true if {
    count(violation) == 0
}

# ---------------------------------------------------------------
# Violation Rule 1 — Privileged Containers
# ---------------------------------------------------------------
# Any container running in privileged mode is a violation.
#
# Symbolically: for each loop iteration i (0..maxItems-1), the
# analyzer creates the path condition:
#   defined(input.containers[i]) AND input.containers[i].privileged == true
# and if satisfiable, adds container.name to the violation set.
#
# This is the "easy" violation — Z3 only needs to set one Boolean
# field to true.
# ---------------------------------------------------------------
violation contains container.name if {
    some container in input.containers     # iterate over every container
    container.privileged == true            # check the privileged flag
}

# ---------------------------------------------------------------
# Violation Rule 2 — Sensitive Container on a Public Host
# ---------------------------------------------------------------
# A container that mounts an unencrypted volume ("sensitive") and
# is scheduled on a public host is a violation.
#
# This rule performs a JOIN between the `sensitive_container` set
# (computed below) and the `input.hosts` collection, matching on
# `container.host_id == host.id`.
#
# Symbolically: Z3 must find values such that:
#   ∃ container ∈ sensitive_container,
#   ∃ host ∈ input.hosts:
#       host.id  == container.host_id   (string equality)
#     ∧ host.public == true             (boolean)
#
# Combined with the sensitive_container rule below, this becomes
# a 3-way join across containers, volumes, and hosts.
# ---------------------------------------------------------------
violation contains container.name if {
    some container in sensitive_container   # draw from the helper set
    some host in input.hosts               # iterate over all hosts
    host.id == container.host_id           # JOIN: host ↔ container
    host.public == true                    # constraint: host is public
}

# ---------------------------------------------------------------
# Helper Rule — Sensitive Container Detection
# ---------------------------------------------------------------
# A container is "sensitive" when it mounts at least one volume
# whose `encrypted` flag is false.
#
# This rule performs a membership test (`volume.id in
# container.volume_ids`) — the Rego `in` operator — which the
# symbolic engine models by enumerating child paths of the
# `volume_ids` array and building an OR-disjunction:
#   volume.id == container.volume_ids[0]
#   OR volume.id == container.volume_ids[1]
#   OR ...
#
# The entire container object is added to the set (not just the
# name), so that Rule 2 can access `.host_id` on the result.
# ---------------------------------------------------------------
sensitive_container contains container if {
    some container in input.containers     # iterate over containers
    some volume in input.volumes           # iterate over volumes
    volume.id in container.volume_ids      # JOIN: volume ↔ container
    volume.encrypted == false              # constraint: unencrypted
}
