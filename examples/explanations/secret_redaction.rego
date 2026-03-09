package demo
import rego.v1

violations contains msg if {
    request := input.requests[_]
    api_token := request.api_token
    request.path == "/admin"
    request.user != "admin"
    msg := sprintf("user %v attempted admin path", [request.user])
}

violations contains msg if {
    request := input.requests[_]
    password := request.password
    count(password) > 0
    request.path == "/login"
    request.user == "guest"
    msg := "guest login included password"
}
