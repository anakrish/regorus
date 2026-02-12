// Allow admins to view the budget file when coming from internal IPs.
permit(principal in User::"admins", action == Action::"view", resource == File::"budget")
when { context.ip like "10.*" };
