# Test string result and abs builtins
package test.builtins2

import future.keywords.if

# Test replace
deny_traversal := true if {
    cleaned := replace(input.path, "../", "")
    cleaned == ""
    contains(input.path, "../")
}

# Test trim_prefix
deny_admin := true if {
    name := trim_prefix(input.name, "admin_")
    name == "root"
}

# Test trim_suffix
deny_backup := true if {
    email := trim_suffix(input.email, ".backup")
    endswith(email, "@evil.com")
}

# Test abs
deny_big_distance := true if {
    d := abs(input.value)
    d > 100
}
