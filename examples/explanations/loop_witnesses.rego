package demo
import rego.v1

public_service[svc] if {
    some i, j
    svc := input.services[_]
    svc.port_ids[_] == input.ports[i].id
    input.ports[i].network == input.networks[j].id
    input.networks[j].public
}

violations contains msg if {
    svc := public_service[_]
    svc.protocols[_] == "http"
    msg := sprintf("public service %v allows http", [svc.name])
}

violations contains msg if {
    svc := public_service[_]
    svc.protocols[_] == "telnet"
    msg := sprintf("public service %v allows telnet", [svc.name])
}
