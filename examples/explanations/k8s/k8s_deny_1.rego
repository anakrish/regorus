package examples.explanations

package k8s
import rego.v1

deny contains msg if {
    container := input.request.object.spec.containers[_]
    not regex.match("^[a-z0-9]+[.]azurecr[.]io/", container.image)
    msg := sprintf("container '%v' uses untrusted registry: %v", [container.name, container.image])
}

deny contains msg if {
    container := input.request.object.spec.containers[_]
    container.securityContext.privileged
    msg := sprintf("container '%v' must not run privileged", [container.name])
}

deny contains msg if {
    container := input.request.object.spec.containers[_]
    not container.resources.limits
    msg := sprintf("container '%v' is missing resource limits", [container.name])
}

deny contains msg if {
    container := input.request.object.spec.containers[_]
    container.securityContext.runAsUser == 0
    msg := sprintf("container '%v' must not run as root (uid 0)", [container.name])
}
