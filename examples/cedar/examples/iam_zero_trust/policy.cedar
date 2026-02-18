// Allow admin login only with MFA from internal IPs.
permit(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.mfa == true && context.ip like "10.*" };

// Block admin login if the account is suspended.
forbid(principal in User::"admins", action == Action::"login", resource == App::"portal")
when { context.suspended == true };
