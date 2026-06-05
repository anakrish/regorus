package test

allow if {
    input.type == "Person"
    input.age > 20
    input.age < 25
}