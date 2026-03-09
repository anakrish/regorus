package demo
import rego.v1

default ship := false

ship if {
    release_branch
    all_required_checks_pass
    count(critical_findings) == 0
}

release_branch if {
    startswith(input.build.branch, "release/")
}

all_required_checks_pass if {
    every check in input.build.required_checks {
        check.passed
    }
}

critical_findings contains msg if {
    dep := input.build.dependencies[_]
    dep.runtime
    dep.license == "GPL-3.0"
    msg := sprintf("runtime dependency %v uses GPL-3.0", [dep.name])
}

critical_findings contains msg if {
    svc := input.services[_]
    svc.public
    svc.auth == "none"
    msg := sprintf("public service %v has no auth", [svc.name])
}
