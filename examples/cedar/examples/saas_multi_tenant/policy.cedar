// Allow viewing a document only when principal and resource share a tenant.
permit(principal, action == Action::"view", resource == Doc::"t1:invoice")
when { principal.tenant == resource.tenant && context.request_tenant == principal.tenant };
