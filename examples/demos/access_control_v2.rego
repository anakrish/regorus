package access_control

default allow := false

allow if {
    not suspended
    authorized
}

# Account is suspended.
suspended if {
    input.user.suspended
}

# Business hours: 9am to 5pm.
business_hours if {
    input.request.hour >= 9
    input.request.hour < 17
}

# Non-sensitive resource.
non_sensitive if {
    input.resource.sensitivity != "sensitive"
}

# Role-based authorization rules.
authorized if {
    input.user.role == "manager"
}

authorized if {
    input.user.role == "employee"
    business_hours
}

authorized if {
    input.user.role == "intern"
    business_hours
    non_sensitive
}
