// Permit Alice to view the report by default.
permit(principal == User::"alice", action == Action::"view", resource == File::"report");

// Explicitly deny if the request is suspended.
forbid(principal == User::"alice", action == Action::"view", resource == File::"report")
when { context.suspended == true };
