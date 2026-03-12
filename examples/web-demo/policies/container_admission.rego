package container_admission

default allow := false

allow := true if {
    count(violation) == 0
}

# Violation: privileged container
violation contains container.name if {
    some container in input.containers
    container.privileged == true
}

# Violation: sensitive container on a public host (3-way join)
violation contains container.name if {
    some container in sensitive_container
    some host in input.hosts
    host.id == container.host_id
    host.public == true
}

# Helper: container mounting an unencrypted volume
sensitive_container contains container if {
    some container in input.containers
    some volume in input.volumes
    volume.id in container.volume_ids
    volume.encrypted == false
}
