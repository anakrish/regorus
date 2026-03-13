package demo
import rego.v1

get_prot(p) := v if {
    protocol := p.protocol
    v := protocol
    protocol != ""
}

violations contains msg if {
    svc := input.services[_]
    prot := get_prot(svc)
    prot == "http"
    msg := sprintf("service %v uses http", [svc.name])
}

get_port(p) := v if {
    v := p.port
}
violations contains msg if {
    svc := input.services[_]
    por := get_port(svc)
    por < 1024
    msg := sprintf("service %v uses privileged port %v", [svc.name, svc.port])
}
