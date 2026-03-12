package network_segmentation

# v2: same DMZ->internal-DB semantics; PII rule DROPPED (more permissive).
# Uses `every` quantifier, lookup maps, and functions instead of partial sets.

default compliant := false

# Lookup maps
zone_of[svc.name] := svc.zone_id if {
    some svc in input.services
}

zone_is_dmz[z.id] := z.dmz if {
    some z in input.zones
}

db_is_internal[d.name] := d.internal if {
    some d in input.databases
}

# Is a service in the DMZ?
in_dmz(svc_name) if {
    zone_id := zone_of[svc_name]
    zone_is_dmz[zone_id] == true
}

# Does a connection target an internal database?
targets_internal_db(conn) if {
    db_is_internal[conn.target] == true
}

# Is a connection a DMZ -> internal-DB violation?
dmz_to_internal(conn) if {
    in_dmz(conn.source)
    targets_internal_db(conn)
}

# Compliant iff no connection is a DMZ->internal-DB violation
compliant if {
    every conn in input.connections {
        not dmz_to_internal(conn)
    }
}
