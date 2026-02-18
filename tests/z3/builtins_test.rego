# Test policy for Z3 string builtins — boolean rules
package test.builtins

import future.keywords.if

# Test startswith — Z3 str.prefixof
deny_prefix := true if {
    startswith(input.name, "admin_")
}

# Test endswith — Z3 str.suffixof
deny_suffix := true if {
    endswith(input.email, "@evil.com")
}

# Test contains — Z3 str.contains
deny_contains := true if {
    contains(input.path, "../")
}

# Test combined string ops
deny_combined := true if {
    startswith(input.url, "http://")
    contains(input.url, "internal")
}

# Test indexof — Z3 str.indexof
has_at_sign := true if {
    indexof(input.email, "@") >= 0
}

# Test trim_prefix
trimmed_name := trim_prefix(input.name, "prefix_")

# Test trim_suffix
trimmed_email := trim_suffix(input.email, ".backup")

# Test replace
cleaned_path := replace(input.path, "../", "")

# Test substring
first_five := substring(input.name, 0, 5)

# Test abs
distance := abs(input.value)
