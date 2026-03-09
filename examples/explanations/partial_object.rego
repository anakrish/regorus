package demo
import rego.v1

violations_by_id[id] := details if {
    resource := input.resources[_]
    id := resource.id
    resource.kind == "pod"
    resource.run_as_root
    details := {
        "message": sprintf("resource %v runs as root", [id]),
        "severity": "high"
    }
}

violations_by_id[id] := details if {
    resource := input.resources[_]
    id := resource.id
    resource.kind == "service"
    resource.exposed
    details := {
        "message": sprintf("service %v is externally exposed", [id]),
        "severity": "medium"
    }
}
