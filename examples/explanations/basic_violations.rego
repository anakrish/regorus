package demo
import rego.v1

violations contains msg if {
    svc := input.services[_]
    svc.protocol == "http"
    msg := sprintf("service %v uses http", [svc.name])
}

violations contains msg if {
    svc := input.services[_]
    svc.port < 1024
    msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
}
