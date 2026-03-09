package demo
import rego.v1

violations contains msg if {
    privileged_public_ports := [port |
        svc := input.services[_]
        svc.public
        port := svc.ports[_]
        port < 1024
    ]
    count(privileged_public_ports) > 0
    msg := sprintf("public services expose privileged ports %v", [privileged_public_ports])
}

violations contains msg if {
    unowned_buckets := [bucket.name |
        bucket := input.buckets[_]
        bucket.owner == ""
    ]
    count(unowned_buckets) > 0
    msg := sprintf("storage buckets without owners: %v", [unowned_buckets])
}
