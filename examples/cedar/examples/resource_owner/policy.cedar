// Allow the resource owner to edit their draft document.
permit(principal, action == Action::"edit", resource == Doc::"draft")
when { principal == resource.owner };
