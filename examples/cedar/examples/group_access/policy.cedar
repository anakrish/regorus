// Allow admins to read or write the plan document.
permit(principal in User::"admins", action in [Action::"read", Action::"write"], resource == Doc::"plan");
