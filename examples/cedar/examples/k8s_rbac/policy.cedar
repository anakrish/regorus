// Kubernetes-style RBAC — namespace-scoped resource access.
//
// Developers can read and list pods in their namespace.
// SREs can additionally delete pods, but only with an
// approved incident ticket and from an on-call session.
// Cluster admins can do everything in production.
// Nobody can delete the kube-system namespace resources.

permit(
  principal in Group::"developers",
  action in [Action::"get", Action::"list"],
  resource == Namespace::"production"
);

permit(
  principal in Group::"sre-oncall",
  action in [Action::"get", Action::"list", Action::"delete"],
  resource == Namespace::"production"
)
when {
  context.has_incident_ticket == true &&
  context.oncall_session == true
};

permit(
  principal in Group::"cluster-admins",
  action in [Action::"get", Action::"list", Action::"delete", Action::"create"],
  resource == Namespace::"production"
);

permit(
  principal in Group::"cluster-admins",
  action in [Action::"get", Action::"list"],
  resource == Namespace::"kube-system"
);

// Hard deny: nobody deletes kube-system resources.
forbid(
  principal,
  action == Action::"delete",
  resource == Namespace::"kube-system"
);
