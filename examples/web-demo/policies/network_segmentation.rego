package network_segmentation

default compliant := false

compliant := true if {
    count(violation) == 0
}

# Violation 1: DMZ service → internal database (4-way join)
violation contains svc.name if {
    some svc in dmz_service
    some conn in input.connections
    conn.source == svc.name
    some db in input.databases
    db.name == conn.target
    db.internal == true
}

# Violation 2: PII service over unencrypted connection
violation contains svc.name if {
    some svc in input.services
    svc.handles_pii == true
    some conn in input.connections
    conn.source == svc.name
    conn.encrypted == false
}

# Helper: services in DMZ zones
dmz_service contains svc if {
    some svc in input.services
    some zone in input.zones
    zone.id == svc.zone_id
    zone.dmz == true
}
