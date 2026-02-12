// Allow cloud admins to read or write a production VM in the us-east region.
permit(principal in Group::"cloud-admins", action in [Action::"read", Action::"write"], resource == Vm::"prod-1")
when { context.region == "us-east" };
