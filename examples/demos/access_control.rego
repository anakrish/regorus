package access_control

default allow := false

# Managers can access any resource at any time.
allow if {
    not input.user.suspended
    input.user.role == "manager"
}

# Regular employees can access resources during business hours.
allow if {
    not input.user.suspended
    input.user.role == "employee"
    input.request.hour >= 9
    input.request.hour < 17
}

# Interns can access non-sensitive resources during business hours.
allow if {
    not input.user.suspended
    input.user.role == "intern"
    input.resource.sensitivity != "sensitive"
    input.request.hour >= 9
    input.request.hour < 17
}
