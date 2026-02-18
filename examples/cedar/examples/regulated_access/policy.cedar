// Allow auditors to read a record only for audit purposes and valid retention.
permit(principal in Role::"auditors", action == Action::"read", resource == Record::"r1")
when { context.purpose == "audit" && context.retention_ok == true };

// Deny audit access when a break-glass flag is set.
forbid(principal in Role::"auditors", action == Action::"read", resource == Record::"r1")
when { context.break_glass == true };
