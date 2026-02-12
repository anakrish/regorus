// Allow owners to edit or comment on internal documents.
permit(principal, action in [Action::"edit", Action::"comment"], resource == Doc::"draft")
when { principal == resource.owner && context.channel like "internal.*" };
