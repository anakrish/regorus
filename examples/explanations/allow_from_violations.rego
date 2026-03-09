package demo
import rego.v1

default allow := false

allow if {
    count(violations) == 0
}

violations contains msg if {
    deployment := input.deployments[_]
    deployment.image == "busybox"
    msg := sprintf("deployment %v uses busybox", [deployment.name])
}

violations contains msg if {
    deployment := input.deployments[_]
    deployment.replicas > 5
    msg := sprintf("deployment %v has too many replicas", [deployment.name])
}
