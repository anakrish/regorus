export const scenarios = [
  {
    id: "allowed-server",
    navTitle: "Allowed Server",
    navSubtitle: "Complete rule with helper-chain causality",
    title: "Complete-rule why chain",
    summary: "A false complete rule keeps the top-level decision readable while preserving the helper chain and loop witness that caused it.",
    focus: "Helper-chain preservation",
    features: ["complete rule", "helper rule", "loop witness", "browser wasm"],
    engine: "rvm",
    query: "data.example.allow",
    whyBindings: false,
    whyFullValues: false,
    whyAllConditions: false,
    policy: `package example
import rego.v1

default allow := false

allow := true if {
    count(violation) == 0
}

violation contains server.id if {
    some server
    public_server[server]
    server.protocols[_] == "http"
}

violation contains server.id if {
    server := input.servers[_]
    server.protocols[_] == "telnet"
}

public_server contains server if {
    some i, j
    server := input.servers[_]
    server.ports[_] == input.ports[i].id
    input.ports[i].network == input.networks[j].id
    input.networks[j].public
}`,
    data: "{}",
    input: `{
  "servers": [
    {"id": "app", "protocols": ["https", "ssh"], "ports": ["p1", "p2", "p3"]},
    {"id": "db", "protocols": ["mysql"], "ports": ["p3"]},
    {"id": "cache", "protocols": ["memcache"], "ports": ["p3"]},
    {"id": "ci", "protocols": ["http"], "ports": ["p1", "p2"]},
    {"id": "busybox", "protocols": ["telnet"], "ports": ["p1"]}
  ],
  "ports": [
    {"id": "p1", "network": "net1"},
    {"id": "p2", "network": "net3"},
    {"id": "p3", "network": "net2"}
  ],
  "networks": [
    {"id": "net1", "public": false},
    {"id": "net2", "public": false},
    {"id": "net3", "public": true},
    {"id": "net4", "public": true}
  ]
}`
  },
  {
    id: "release-gate",
    navTitle: "Release Gate",
    navSubtitle: "Decision rule plus every witness",
    title: "Release decisions with causal witnesses",
    summary: "This example shows a top-level ship decision carrying helper successes and failing findings into one causal explanation.",
    focus: "Decision + helper + every",
    features: ["every", "complete decision", "supporting findings", "all contributing"],
    engine: "rvm",
    query: "data.demo.ship",
    whyBindings: false,
    whyFullValues: false,
    whyAllConditions: true,
    policy: `package demo
import rego.v1

default ship := false

ship if {
    release_branch
    all_required_checks_pass
    count(critical_findings) == 0
}

release_branch if {
    startswith(input.build.branch, "release/")
}

all_required_checks_pass if {
    every check in input.build.required_checks {
        check.passed
    }
}

critical_findings contains msg if {
    dep := input.build.dependencies[_]
    dep.runtime
    dep.license == "GPL-3.0"
    msg := sprintf("runtime dependency %v uses GPL-3.0", [dep.name])
}

critical_findings contains msg if {
    svc := input.services[_]
    svc.public
    svc.auth == "none"
    msg := sprintf("public service %v has no auth", [svc.name])
}`,
    data: "{}",
    input: `{
  "build": {
    "branch": "release/2026.03",
    "required_checks": [
      {"name": "unit", "passed": true},
      {"name": "integration", "passed": true},
      {"name": "sbom", "passed": true}
    ],
    "dependencies": [
      {"name": "openssl", "runtime": true, "license": "Apache-2.0"},
      {"name": "legacy-crypto", "runtime": true, "license": "GPL-3.0"}
    ]
  },
  "services": [
    {"name": "public-api", "public": true, "auth": "oauth2"},
    {"name": "debug-ui", "public": true, "auth": "none"}
  ]
}`
  },
  {
    id: "fraud-signals",
    navTitle: "Fraud Signals",
    navSubtitle: "Many contributing conditions in one alert",
    title: "Stacked evidence for suspicious activity",
    summary: "All-contributing mode makes one alert show a compact set of builtin, comparison, and negation signals that justify the result.",
    focus: "All-contributing evidence",
    features: ["multiple findings", "builtins", "comparisons", "negation"],
    engine: "rvm",
    query: "data.demo.alerts",
    whyBindings: false,
    whyFullValues: false,
    whyAllConditions: true,
    policy: `package demo
import rego.v1

alerts contains msg if {
    txn := input.transactions[_]
    startswith(lower(txn.merchant), "gift")
    txn.amount >= 500
    txn.country != input.account.home_country
    not txn.card_present
    msg := sprintf("transaction %v looks like gift-card laundering", [txn.id])
}

alerts contains msg if {
    txn := input.transactions[_]
    endswith(lower(txn.merchant), ".ru")
    txn.amount > 100
    msg := sprintf("transaction %v targets suspicious merchant domain", [txn.id])
}`,
    data: "{}",
    input: `{
  "account": {
    "home_country": "US"
  },
  "transactions": [
    {
      "id": "tx-100",
      "merchant": "gift galaxy",
      "amount": 1200,
      "country": "MT",
      "card_present": false
    },
    {
      "id": "tx-101",
      "merchant": "compute-hub.ru",
      "amount": 240,
      "country": "US",
      "card_present": true
    },
    {
      "id": "tx-102",
      "merchant": "coffee-stop",
      "amount": 8,
      "country": "US",
      "card_present": true
    }
  ]
}`
  },
  {
    id: "timezone-negated",
    navTitle: "Negated Helper",
    navSubtitle: "Surface the failing inner condition",
    title: "Negation that still explains itself",
    summary: "Instead of only returning the outer not expression, why output reaches into the helper rule and exposes the failing inner condition.",
    focus: "Negated helper inlining",
    features: ["negation", "helper rule", "inner failing condition"],
    engine: "interpreter",
    query: "data.demo.violations",
    whyBindings: false,
    whyFullValues: false,
    whyAllConditions: false,
    policy: `package demo
import rego.v1

valid_clock_time_zone if {
    clock_timezone := data.config.DEVICE_METADATA.localhost
    clock_timezone.timezone == "UTC"
}

violations contains msg if {
    not valid_clock_time_zone
    msg := "The clock timezone is not set to UTC"
}`,
    data: `{
  "config": {
    "DEVICE_METADATA": {
      "localhost": {
        "timezone": "PST"
      }
    }
  }
}`,
    input: "{}"
  },
  {
    id: "secret-redaction",
    navTitle: "Secret Redaction",
    navSubtitle: "Compare redacted and full-value modes",
    title: "Reason capture without leaking secrets",
    summary: "The safe default keeps secret-looking values redacted while still preserving the causal record.",
    focus: "Redacted vs full values",
    features: ["binding capture", "secret awareness", "safe defaults"],
    engine: "interpreter",
    query: "data.demo.violations",
    whyBindings: true,
    whyFullValues: false,
    whyAllConditions: true,
    policy: `package demo
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
}`,
    data: "{}",
    input: `{
  "requests": [
    {
      "user": "alice",
      "path": "/admin",
      "api_token": "tok-prod-123",
      "password": ""
    },
    {
      "user": "guest",
      "path": "/login",
      "api_token": "",
      "password": "guest-password"
    }
  ]
}`
  }
];