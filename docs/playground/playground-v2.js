// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Import the WASM module
import init, { Engine } from './pkg/regorusjs.js';

// Regorus Playground JavaScript
// Interactive policy evaluation with Monaco Editor and WASM

// Global state
let regorusEngine = null;
let editors = {};
let isInitialized = false;
let lastCoverageReport = null;
let coverageDecorations = [];

// Comprehensive example policies and data
const examples = {
    // Security & Authorization
    'server-policy': {
        name: 'Server Security Policy',
        policy: `package example

default allow := false

allow if {
    count(violation) == 0
}

violation[server.id] if {
    some server
    public_server[server]
    server.protocols[_] == "http"
}

violation[server.id] if {
    server := input.servers[_]
    server.protocols[_] == "telnet"
}

public_server[server] if {
    some i, j
    server := input.servers[_]
    server.ports[_] == input.ports[i].id
    input.ports[i].network == input.networks[j].id
    input.networks[j].public
}`,
        input: `{
    "servers": [
        {"id": "app", "protocols": ["https", "ssh"], "ports": ["p1", "p2", "p3"]},
        {"id": "db", "protocols": ["mysql"], "ports": ["p3"]},
        {"id": "cache", "protocols": ["memcache"], "ports": ["p3"]},
        {"id": "ci", "protocols": ["http"], "ports": ["p1", "p2"]},
        {"id": "busybox", "protocols": ["telnet"], "ports": ["p1"]}
    ],
    "networks": [
        {"id": "net1", "public": false},
        {"id": "net2", "public": false},
        {"id": "net3", "public": true},
        {"id": "net4", "public": true}
    ],
    "ports": [
        {"id": "p1", "network": "net1"},
        {"id": "p2", "network": "net3"},
        {"id": "p3", "network": "net2"}
    ]
}`,
        data: '{}',
        query: 'data.example.allow'
    },
    
    'simple-rbac': {
        name: 'Simple RBAC',
        policy: `package rbac

import rego.v1

default allow := false

allow if {
    user_has_permission(input.user, input.action, input.resource)
}

user_has_permission(user, action, resource) if {
    permission := data.permissions[user][_]
    permission.action == action
    permission.resource == resource
}

user_has_permission(user, action, resource) if {
    role := data.user_roles[user][_]
    role_has_permission(role, action, resource)
}

role_has_permission(role, action, resource) if {
    permission := data.role_permissions[role][_]
    permission.action == action
    permission.resource == resource
}`,
        input: `{
    "user": "alice",
    "action": "read", 
    "resource": "document1"
}`,
        data: `{
    "user_roles": {
        "alice": ["editor"],
        "bob": ["viewer"]
    },
    "role_permissions": {
        "editor": [
            {"action": "read", "resource": "document1"},
            {"action": "write", "resource": "document1"}
        ],
        "viewer": [
            {"action": "read", "resource": "document1"}
        ]
    },
    "permissions": {}
}`,
        query: 'data.rbac.allow'
    },

    'api-authorization': {
        name: 'API Authorization',
        policy: `package api

import rego.v1

default allow := false

# Allow GET requests to public endpoints
allow if {
    input.method == "GET"
    startswith(input.path, "/public/")
}

# Allow authenticated users to access their own resources
allow if {
    input.token
    claims := io.jwt.decode_verify(input.token, {"secret": data.jwt_secret})
    user_id := claims[1].sub
    input.path == sprintf("/users/%s", [user_id])
}

# Allow admin users full access
allow if {
    input.token
    claims := io.jwt.decode_verify(input.token, {"secret": data.jwt_secret})
    claims[1].role == "admin"
}

# Rate limiting check
rate_limit_exceeded if {
    count(data.requests[input.client_ip]) > data.rate_limit
}`,
        input: `{
    "method": "GET",
    "path": "/users/alice",
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsInJvbGUiOiJ1c2VyIn0.example",
    "client_ip": "192.168.1.100"
}`,
        data: `{
    "jwt_secret": "secret123",
    "rate_limit": 100,
    "requests": {
        "192.168.1.100": ["req1", "req2", "req3"]
    }
}`,
        query: 'data.api.allow'
    },

    'kubernetes-admission': {
        name: 'Kubernetes Admission Control',
        policy: `package kubernetes.admission

import rego.v1

# Deny pods without resource limits
deny[msg] if {
    input.request.kind.kind == "Pod"
    input.request.operation == "CREATE"
    not input.request.object.spec.containers[_].resources.limits
    msg := "Containers must have resource limits defined"
}

# Deny privileged containers
deny[msg] if {
    input.request.kind.kind == "Pod"
    input.request.object.spec.containers[_].securityContext.privileged
    msg := "Privileged containers are not allowed"
}

# Require specific labels
deny[msg] if {
    input.request.kind.kind == "Pod"
    input.request.operation == "CREATE"
    not input.request.object.metadata.labels.app
    msg := "All pods must have an 'app' label"
}

# Check image registry
deny[msg] if {
    input.request.kind.kind == "Pod"
    container := input.request.object.spec.containers[_]
    not startswith(container.image, "registry.company.com/")
    msg := sprintf("Image %s is not from approved registry", [container.image])
}`,
        input: `{
    "request": {
        "kind": {"kind": "Pod"},
        "operation": "CREATE",
        "object": {
            "metadata": {
                "name": "test-pod",
                "labels": {"app": "web"}
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "nginx:1.20",
                    "resources": {
                        "limits": {"cpu": "100m", "memory": "128Mi"}
                    },
                    "securityContext": {"privileged": false}
                }]
            }
        }
    }
}`,
        data: '{}',
        query: 'data.kubernetes.admission.deny'
    },

    'jwt-validation': {
        name: 'JWT Token Validation',
        policy: `package jwt

import rego.v1

default valid := false

# Validate JWT structure and signature
valid if {
    input.token
    io.jwt.verify_hs256(input.token, data.secret)
    payload := io.jwt.decode(input.token)[1]
    payload.exp > time.now_ns() / 1000000000  # Check expiration
    payload.iss == data.expected_issuer        # Check issuer
}

# Extract user info from valid token
user_info := payload if {
    valid
    payload := io.jwt.decode(input.token)[1]
}

# Check if user has required scope
has_scope(required_scope) if {
    valid
    payload := io.jwt.decode(input.token)[1]
    required_scope in payload.scopes
}`,
        input: `{
    "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSIsImlzcyI6Im15LWFwcCIsImV4cCI6OTk5OTk5OTk5OSwic2NvcGVzIjpbInJlYWQiLCJ3cml0ZSJdfQ.example"
}`,
        data: `{
    "secret": "my-secret-key",
    "expected_issuer": "my-app"
}`,
        query: 'data.jwt.valid'
    },

    // Data Processing
    'data-filtering': {
        name: 'Data Filtering',
        policy: `package data_filter

import rego.v1

# Filter sensitive data based on user role
filtered_data := result if {
    input.user_role == "admin"
    result := data.sensitive_data
} else := result if {
    input.user_role == "user"
    result := {k: v | 
        some k, v in data.sensitive_data
        not k in {"ssn", "salary", "internal_notes"}
    }
} else := {} if {
    input.user_role == "guest"
}

# Check what fields are allowed for a role
allowed_fields[field] if {
    input.user_role == "admin"
    some field in object.keys(data.sensitive_data)
}

allowed_fields[field] if {
    input.user_role == "user"
    some field in object.keys(data.sensitive_data)
    not field in {"ssn", "salary", "internal_notes"}
}`,
        input: `{
    "user_role": "user"
}`,
        data: `{
    "sensitive_data": {
        "name": "John Doe",
        "email": "john@example.com",
        "department": "Engineering",
        "ssn": "123-45-6789",
        "salary": 75000,
        "phone": "555-0123",
        "internal_notes": "High performer, consider for promotion"
    }
}`,
        query: 'data.data_filter.filtered_data'
    },

    'data-validation': {
        name: 'Data Validation',
        policy: `package validation

import rego.v1

# Validate user registration data
valid_user if {
    input.email
    contains(input.email, "@")
    input.age >= 18
    input.password
    count(input.password) >= 8
}

# Email validation
valid_email if {
    regex.match("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", input.email)
}

# Password strength validation
strong_password if {
    count(input.password) >= 12
    regex.match("[A-Z]", input.password)  # Uppercase
    regex.match("[a-z]", input.password)  # Lowercase
    regex.match("[0-9]", input.password)  # Number
    regex.match("[^a-zA-Z0-9]", input.password)  # Special char
}

# Validation errors
errors[msg] if {
    not input.email
    msg := "Email is required"
}

errors[msg] if {
    input.email
    not valid_email
    msg := "Invalid email format"
}

errors[msg] if {
    not input.password
    msg := "Password is required"
}

errors[msg] if {
    input.password
    count(input.password) < 8
    msg := "Password must be at least 8 characters"
}`,
        input: `{
    "email": "user@example.com",
    "password": "MyStr0ng!Pass",
    "age": 25,
    "name": "John Doe"
}`,
        data: '{}',
        query: 'data.validation.valid_user'
    },

    'schema-validation': {
        name: 'Schema Validation',
        policy: `package schema

import rego.v1

# Validate API request schema
valid_request if {
    # Check required fields
    required_fields := {"name", "email", "type"}
    all_required_present
    
    # Check field types
    is_string(input.name)
    is_string(input.email)
    input.type in allowed_types
}

all_required_present if {
    required_fields := {"name", "email", "type"}
    count({f | some f in required_fields; input[f]}) == count(required_fields)
}

allowed_types := {"user", "admin", "guest"}

# Validate nested objects
valid_address if {
    input.address.street
    input.address.city
    input.address.country
    regex.match("^[0-9]{5}$", input.address.zip)
}

# Check array constraints
valid_tags if {
    count(input.tags) <= 10
    all(input.tags, func(tag) { count(tag) <= 50 })
}

schema_errors[msg] if {
    not input.name
    msg := "Field 'name' is required"
}

schema_errors[msg] if {
    not input.type in allowed_types
    msg := sprintf("Field 'type' must be one of: %v", [allowed_types])
}`,
        input: `{
    "name": "John Doe",
    "email": "john@example.com",
    "type": "user",
    "address": {
        "street": "123 Main St",
        "city": "Anytown",
        "country": "US",
        "zip": "12345"
    },
    "tags": ["developer", "golang", "kubernetes"]
}`,
        data: '{}',
        query: 'data.schema.valid_request'
    },

    'data-transformation': {
        name: 'Data Transformation',
        policy: `package transform

import rego.v1

# Transform user data for API response
transformed_user := {
    "id": input.user.id,
    "display_name": display_name,
    "contact": contact_info,
    "permissions": user_permissions,
    "last_login": format_date(input.user.last_login)
}

display_name := input.user.full_name if {
    input.user.full_name != ""
} else := sprintf("%s %s", [input.user.first_name, input.user.last_name])

contact_info := {
    "email": input.user.email,
    "phone": masked_phone
}

masked_phone := sprintf("***-%s", [substring(input.user.phone, 7, -1)]) if {
    count(input.user.phone) == 10
} else := "***-****"

user_permissions[perm] if {
    role := data.user_roles[input.user.id]
    perm := data.role_permissions[role][_]
}

format_date(timestamp) := date if {
    date := time.format(timestamp * 1000000000, "2006-01-02", "UTC")
}`,
        input: `{
    "user": {
        "id": "user123",
        "first_name": "John",
        "last_name": "Doe",
        "full_name": "",
        "email": "john@example.com",
        "phone": "5551234567",
        "last_login": 1640995200
    }
}`,
        data: `{
    "user_roles": {
        "user123": "editor"
    },
    "role_permissions": {
        "editor": ["read", "write", "edit"],
        "viewer": ["read"]
    }
}`,
        query: 'data.transform.transformed_user'
    },

    // Network & Infrastructure
    'network-policy': {
        name: 'Network Policy',
        policy: `package network

import rego.v1

# Allow internal network traffic
allow if {
    is_internal_network(input.source_ip)
    is_internal_network(input.dest_ip)
}

# Allow specific service communications
allow if {
    input.source_service in data.allowed_services[input.dest_service]
}

# Block suspicious traffic
deny if {
    input.source_ip in data.blocked_ips
}

deny if {
    input.dest_port in data.blocked_ports
}

is_internal_network(ip) if {
    net.cidr_contains("10.0.0.0/8", ip)
}

is_internal_network(ip) if {
    net.cidr_contains("192.168.0.0/16", ip)
}

# Rate limiting per IP
rate_limited if {
    count(data.recent_requests[input.source_ip]) > data.rate_limit
}`,
        input: `{
    "source_ip": "10.1.1.100",
    "dest_ip": "10.1.2.50",
    "dest_port": 443,
    "source_service": "web",
    "dest_service": "api"
}`,
        data: `{
    "allowed_services": {
        "api": ["web", "mobile"],
        "database": ["api"],
        "cache": ["api", "web"]
    },
    "blocked_ips": ["1.2.3.4", "5.6.7.8"],
    "blocked_ports": [23, 135, 139],
    "rate_limit": 1000,
    "recent_requests": {
        "10.1.1.100": ["req1", "req2"]
    }
}`,
        query: 'data.network.allow'
    },

    'firewall-rules': {
        name: 'Firewall Rules',
        policy: `package firewall

import rego.v1

default action := "deny"

# Allow established connections
action := "allow" if {
    input.state == "established"
}

# Allow outbound web traffic
action := "allow" if {
    input.direction == "outbound"
    input.dest_port in {80, 443}
    input.protocol == "tcp"
}

# Allow SSH from admin networks
action := "allow" if {
    input.dest_port == 22
    input.protocol == "tcp"
    input.source_ip in data.admin_networks
}

# Allow DNS
action := "allow" if {
    input.dest_port == 53
    input.protocol in {"tcp", "udp"}
}

# Block known bad IPs
action := "deny" if {
    input.source_ip in data.threat_ips
}

# Log high-risk traffic
log_required if {
    input.dest_port in data.sensitive_ports
}

log_required if {
    input.source_ip in data.monitored_ips
}`,
        input: `{
    "direction": "inbound",
    "source_ip": "203.0.113.1",
    "dest_port": 22,
    "protocol": "tcp",
    "state": "new"
}`,
        data: `{
    "admin_networks": ["203.0.113.0/24", "198.51.100.0/24"],
    "threat_ips": ["1.2.3.4", "5.6.7.8"],
    "sensitive_ports": [22, 3389, 23],
    "monitored_ips": ["203.0.113.1"]
}`,
        query: 'data.firewall.action'
    },

    // Application Logic
    'feature-flags': {
        name: 'Feature Flags',
        policy: `package feature_flags

import rego.v1

# Check if feature is enabled for user
feature_enabled(feature_name) if {
    feature := data.features[feature_name]
    feature.enabled
    user_matches_criteria(feature)
}

user_matches_criteria(feature) if {
    not feature.criteria  # No criteria means enabled for all
}

user_matches_criteria(feature) if {
    feature.criteria.user_percentage
    user_hash := crypto.sha256(input.user_id)
    user_bucket := to_number(substring(user_hash, 0, 8), 16) % 100
    user_bucket < feature.criteria.user_percentage
}

user_matches_criteria(feature) if {
    feature.criteria.user_groups
    input.user_group in feature.criteria.user_groups
}

user_matches_criteria(feature) if {
    feature.criteria.beta_users
    input.user_id in feature.criteria.beta_users
}

# Get all enabled features for user
enabled_features[feature_name] if {
    some feature_name, _ in data.features
    feature_enabled(feature_name)
}`,
        input: `{
    "user_id": "user123",
    "user_group": "premium"
}`,
        data: `{
    "features": {
        "new_ui": {
            "enabled": true,
            "criteria": {
                "user_percentage": 50
            }
        },
        "advanced_analytics": {
            "enabled": true,
            "criteria": {
                "user_groups": ["premium", "enterprise"]
            }
        },
        "beta_feature": {
            "enabled": true,
            "criteria": {
                "beta_users": ["user456", "user789"]
            }
        },
        "global_feature": {
            "enabled": true
        }
    }
}`,
        query: 'data.feature_flags.enabled_features'
    },

    'rate-limiting': {
        name: 'Rate Limiting',
        policy: `package rate_limit

import rego.v1

default allow := true
default reset_time := 0

# Check if request is within rate limit
allow if {
    not exceeded
}

exceeded if {
    bucket := get_bucket(input.client_id, input.window)
    bucket.count >= bucket.limit
}

# Get rate limit bucket for client
get_bucket(client_id, window) := bucket if {
    bucket_key := sprintf("%s:%s", [client_id, window])
    bucket := data.rate_limits[bucket_key]
} else := {
    "count": 0,
    "limit": default_limit(input.endpoint),
    "window_start": time.now_ns()
}

# Default limits per endpoint
default_limit(endpoint) := 1000 if {
    endpoint == "/api/search"
} else := 100 if {
    startswith(endpoint, "/api/")
} else := 10 if {
    endpoint == "/api/upload"
} else := 60

# Calculate when limit resets
reset_time := bucket.window_start + (input.window_seconds * 1000000000) if {
    bucket := get_bucket(input.client_id, input.window)
}

# Check if client needs special treatment
vip_client if {
    input.client_id in data.vip_clients
}

# Higher limits for VIP clients
get_bucket(client_id, window) := bucket if {
    vip_client
    bucket_key := sprintf("%s:%s", [client_id, window])
    bucket := data.rate_limits[bucket_key]
    bucket_with_vip_limit := object.union(bucket, {"limit": bucket.limit * 10})
    bucket := bucket_with_vip_limit
}`,
        input: `{
    "client_id": "client123",
    "endpoint": "/api/users",
    "window": "minute",
    "window_seconds": 60
}`,
        data: `{
    "rate_limits": {
        "client123:minute": {
            "count": 45,
            "limit": 100,
            "window_start": 1640995200000000000
        }
    },
    "vip_clients": ["vip_client1", "vip_client2"]
}`,
        query: 'data.rate_limit.allow'
    }
};

// Simple initialization without Monaco Editor first
async function initPlayground() {
    const loadingOverlay = document.getElementById('loading-overlay');
    
    try {
        console.log('Starting playground initialization...');
        
        // Step 1: Initialize WASM
        updateLoadingMessage('Loading Regorus WASM module...');
        console.log('Initializing WASM...');
        await init();
        console.log('WASM initialized successfully');
        
        // Step 2: Create engine
        updateLoadingMessage('Creating Regorus engine...');
        console.log('Creating engine...');
        regorusEngine = new Engine();
        console.log('Engine created successfully');
        
        // Step 3: Initialize editors
        updateLoadingMessage('Initializing code editors...');
        console.log('Initializing editors...');
        await initializeEditors();
        console.log('Editors initialized successfully');
        
        // Step 4: Set up event listeners
        console.log('Setting up event listeners...');
        setupEventListeners();
        
        // Step 5: Load default example
        console.log('Loading default example...');
        loadExample('server-policy');
        
        // Step 6: Hide loading overlay
        loadingOverlay.classList.add('hidden');
        isInitialized = true;
        updateStatus('Ready');
        console.log('Playground initialization completed');
        
    } catch (error) {
        console.error('Initialization failed:', error);
        showError(`Failed to initialize playground: ${error.message}`, error);
    }
}

function updateLoadingMessage(message) {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.innerHTML = `
        <div class="loading-spinner"></div>
        <p>${message}</p>
    `;
}

function showError(message, error) {
    const loadingOverlay = document.getElementById('loading-overlay');
    loadingOverlay.innerHTML = `
        <div style="color: #f48771; text-align: center; padding: 20px; max-width: 500px;">
            <h3>❌ Initialization Failed</h3>
            <p><strong>${message}</strong></p>
            <details style="margin: 16px 0; text-align: left;">
                <summary style="cursor: pointer;">Show technical details</summary>
                <pre style="font-size: 0.8rem; overflow: auto; max-height: 200px; background: #2d1b1b; padding: 8px; border-radius: 4px; margin-top: 8px;">${error.stack || error.message}</pre>
            </details>
            <button onclick="location.reload()" style="margin-top: 16px; padding: 10px 20px; background: #0e639c; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 0.9rem;">
                🔄 Retry
            </button>
        </div>
    `;
}

// Initialize editors using a timeout approach for better error handling
async function initializeEditors() {
    return new Promise((resolve, reject) => {
        // Set a timeout to prevent infinite loading
        const timeout = setTimeout(() => {
            reject(new Error('Editor initialization timed out'));
        }, 30000); // 30 seconds timeout
        
        try {
            // Configure Monaco loader
            require.config({ 
                paths: { 
                    vs: 'https://cdnjs.cloudflare.com/ajax/libs/monaco-editor/0.44.0/min/vs' 
                }
            });
            
            // Load Monaco Editor
            require(['vs/editor/editor.main'], function() {
                try {
                    clearTimeout(timeout);
                    
                    // Define enhanced Rego language support
                    monaco.languages.register({ id: 'rego' });
                    monaco.languages.setMonarchTokensProvider('rego', {
                        tokenizer: {
                            root: [
                                // Keywords
                                [/\b(package|import|as|default|if|else|some|every|in|contains|with|not|true|false|null)\b/, 'keyword'],
                                
                                // Built-in functions
                                [/\b(count|sum|max|min|sort|all|any|sprintf|regex|startswith|endswith|substring|split|lower|upper|trim|format_int|to_number|time|crypto|net|io|json|yaml|base64|uuid)\b/, 'keyword.function'],
                                
                                // Operators
                                [/:=|==|!=|<=|>=|<|>|\+|-|\*|\/|%|\||&/, 'operator'],
                                
                                // Comments
                                [/#.*$/, 'comment'],
                                
                                // Strings
                                [/"([^"\\\\]|\\\\.)*$/, 'string.invalid'],
                                [/"/, { token: 'string.quote', bracket: '@open', next: '@string' }],
                                [/`/, { token: 'string.quote', bracket: '@open', next: '@rawstring' }],
                                
                                // Numbers
                                [/\d*\.\d+([eE][\-+]?\d+)?/, 'number.float'],
                                [/0[xX][0-9a-fA-F]+/, 'number.hex'],
                                [/\d+/, 'number'],
                                
                                // Variables and identifiers
                                [/[a-zA-Z_][a-zA-Z0-9_]*/, 'identifier'],
                                
                                // Brackets
                                [/[{}()\[\]]/, '@brackets'],
                                
                                // Delimiters
                                [/[;,.]/, 'delimiter'],
                            ],
                            string: [
                                [/[^\\\\"]+/, 'string'],
                                [/\\\\./, 'string.escape'],
                                [/"/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
                            ],
                            rawstring: [
                                [/[^`]+/, 'string'],
                                [/`/, { token: 'string.quote', bracket: '@close', next: '@pop' }]
                            ]
                        }
                    });

                    // Set language configuration for better editing experience
                    monaco.languages.setLanguageConfiguration('rego', {
                        comments: {
                            lineComment: '#'
                        },
                        brackets: [
                            ['{', '}'],
                            ['[', ']'],
                            ['(', ')']
                        ],
                        autoClosingPairs: [
                            { open: '{', close: '}' },
                            { open: '[', close: ']' },
                            { open: '(', close: ')' },
                            { open: '"', close: '"' },
                            { open: '`', close: '`' }
                        ],
                        surroundingPairs: [
                            { open: '{', close: '}' },
                            { open: '[', close: ']' },
                            { open: '(', close: ')' },
                            { open: '"', close: '"' },
                            { open: '`', close: '`' }
                        ]
                    });
                    
                    // Create editors with proper Rego support
                    editors.policy = monaco.editor.create(document.getElementById('policy-editor'), {
                        value: '',
                        language: 'rego',
                        theme: 'vs',
                        minimap: { enabled: false },
                        fontSize: 13,
                        lineNumbers: 'on',
                        wordWrap: 'on',
                        automaticLayout: true,
                        tabSize: 4,
                        insertSpaces: true,
                        formatOnPaste: true,
                        formatOnType: true,
                    });

                    editors.input = monaco.editor.create(document.getElementById('input-editor'), {
                        value: '{}',
                        language: 'json',
                        theme: 'vs',
                        minimap: { enabled: false },
                        fontSize: 13,
                        lineNumbers: 'on',
                        wordWrap: 'on',
                        automaticLayout: true,
                    });

                    editors.data = monaco.editor.create(document.getElementById('data-editor'), {
                        value: '{}',
                        language: 'json',
                        theme: 'vs',
                        minimap: { enabled: false },
                        fontSize: 13,
                        lineNumbers: 'on',
                        wordWrap: 'on',
                        automaticLayout: true,
                    });
                    
                    console.log('Editors created successfully');
                    resolve();
                    
                } catch (editorError) {
                    clearTimeout(timeout);
                    console.error('Error creating editors:', editorError);
                    reject(editorError);
                }
            }, (requireError) => {
                clearTimeout(timeout);
                console.error('Error loading Monaco Editor:', requireError);
                reject(new Error(`Failed to load Monaco Editor: ${requireError}`));
            });
            
        } catch (error) {
            clearTimeout(timeout);
            reject(error);
        }
    });
}

// Set up event listeners
function setupEventListeners() {
    // Evaluate button
    document.getElementById('evaluate-btn').addEventListener('click', evaluatePolicy);
    
    // Clear button
    document.getElementById('clear-btn').addEventListener('click', clearAll);
    
    // Examples dropdown
    document.getElementById('examples-select').addEventListener('change', (e) => {
        if (e.target.value) {
            loadExample(e.target.value);
        }
    });
    
    // Format buttons
    document.querySelectorAll('.format-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const editorType = e.target.getAttribute('data-editor');
            formatEditor(editorType);
        });
    });
    
    // Coverage checkbox
    document.getElementById('coverage-enabled').addEventListener('change', (e) => {
        if (!e.target.checked) {
            clearCoverage();
        }
    });
    
    // Layout selector
    document.getElementById('layout-select').addEventListener('change', (e) => {
        changeLayout(e.target.value);
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
        if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
            e.preventDefault();
            evaluatePolicy();
        }
    });
}

// Load an example
function loadExample(exampleKey) {
    const example = examples[exampleKey];
    if (!example || !editors.policy) return;
    
    editors.policy.setValue(example.policy);
    editors.input.setValue(example.input);
    editors.data.setValue(example.data);
    document.getElementById('query-input').value = example.query;
    
    document.getElementById('examples-select').value = exampleKey;
    updateStatus(`Loaded example: ${example.name}`);
}

// Clear all editors
function clearAll() {
    if (!editors.policy) return;
    
    editors.policy.setValue('');
    editors.input.setValue('{}');
    editors.data.setValue('{}');
    document.getElementById('query-input').value = 'data';
    document.getElementById('examples-select').value = '';
    clearCoverage();
    clearOutput();
    updateStatus('Cleared');
}

// Format editor content
function formatEditor(editorType) {
    const editor = editors[editorType];
    if (!editor) return;
    
    try {
        if (editorType !== 'policy') {
            // For JSON, parse and reformat
            const content = editor.getValue();
            if (content.trim()) {
                const parsed = JSON.parse(content);
                const formatted = JSON.stringify(parsed, null, 2);
                editor.setValue(formatted);
            }
        }
    } catch (error) {
        updateStatus(`Format error: ${error.message}`, true);
    }
}

// Evaluate policy
async function evaluatePolicy() {
    if (!isInitialized || !regorusEngine) {
        updateStatus('Playground not ready', true);
        return;
    }
    
    try {
        updateStatus('Evaluating...');
        const startTime = performance.now();
        
        // Get input values
        const policy = editors.policy.getValue();
        const inputData = editors.input.getValue();
        const data = editors.data.getValue();
        const query = document.getElementById('query-input').value || 'data';
        
        if (!policy.trim()) {
            throw new Error('Policy cannot be empty');
        }
        
        // Create new engine for clean state
        const engine = new Engine();
        
        // Enable coverage if checkbox is checked
        const coverageEnabled = document.getElementById('coverage-enabled').checked;
        if (coverageEnabled) {
            engine.setEnableCoverage(true);
        }
        
        // Add policy
        console.log('Adding policy...');
        engine.addPolicy('playground.rego', policy);
        
        // Set input data if provided
        if (inputData.trim() && inputData.trim() !== '{}') {
            console.log('Setting input data...');
            engine.setInputJson(inputData);
        }
        
        // Add data if provided
        if (data.trim() && data.trim() !== '{}') {
            console.log('Adding data...');
            engine.addDataJson(data);
        }
        
        // Evaluate query
        console.log(`Evaluating query: ${query}`);
        const result = engine.evalRule(query);
        const endTime = performance.now();
        const executionTime = (endTime - startTime).toFixed(2);
        
        // Get coverage report if enabled
        let coverageReport = null;
        if (coverageEnabled) {
            try {
                coverageReport = engine.getCoverageReport();
                lastCoverageReport = JSON.parse(coverageReport);
                displayCoverage(lastCoverageReport);
            } catch (coverageError) {
                console.warn('Failed to get coverage report:', coverageError);
            }
        } else {
            clearCoverage();
        }
        
        // Display result
        displayResult(result, true, executionTime, coverageReport);
        updateStatus('Evaluation completed');
        
    } catch (error) {
        console.error('Evaluation error:', error);
        displayResult(error.message, false);
        updateStatus('Evaluation failed', true);
    }
}

// Display evaluation result
function displayResult(result, isSuccess, executionTime = null, coverageReport = null) {
    const outputPanel = document.getElementById('output-panel');
    const evaluationTimeElement = document.getElementById('evaluation-time');
    
    outputPanel.innerHTML = '';
    
    if (isSuccess) {
        try {
            // Parse and format the JSON result
            const parsed = JSON.parse(result);
            const formatted = JSON.stringify(parsed, null, 2);
            
            const coverageInfo = coverageReport && lastCoverageReport ? 
                `<div class="coverage-summary">
                    <h4>📊 Coverage Summary:</h4>
                    <p><strong>Files:</strong> ${Object.keys(lastCoverageReport.files || {}).length}</p>
                    <p><strong>Covered Lines:</strong> ${getCoveredLinesCount()}</p>
                    <p><strong>Total Lines:</strong> ${getTotalLinesCount()}</p>
                    <p><strong>Coverage:</strong> ${getCoveragePercentage()}%</p>
                    <p><em>💡 Coverage is highlighted in the policy editor</em></p>
                </div>` : '';
            
            outputPanel.innerHTML = `
                <div class="output-result output-success">
                    <div class="result-header">
                        <strong>✅ Evaluation Result:</strong>
                    </div>
                    <pre class="output-json">${formatted}</pre>
                    ${coverageInfo}
                </div>
            `;
        } catch (e) {
            // If not valid JSON, display as string
            const coverageInfo = coverageReport && lastCoverageReport ? 
                `<div class="coverage-summary">
                    <h4>📊 Coverage Summary:</h4>
                    <p><strong>Files:</strong> ${Object.keys(lastCoverageReport.files || {}).length}</p>
                    <p><strong>Covered Lines:</strong> ${getCoveredLinesCount()}</p>
                    <p><strong>Total Lines:</strong> ${getTotalLinesCount()}</p>
                    <p><strong>Coverage:</strong> ${getCoveragePercentage()}%</p>
                    <p><em>💡 Coverage is highlighted in the policy editor</em></p>
                </div>` : '';
            
            outputPanel.innerHTML = `
                <div class="output-result output-success">
                    <div class="result-header">
                        <strong>✅ Evaluation Result:</strong>
                    </div>
                    <pre class="output-json">${result}</pre>
                    ${coverageInfo}
                </div>
            `;
        }
        
        if (executionTime) {
            evaluationTimeElement.textContent = `Executed in ${executionTime}ms`;
        }
    } else {
        outputPanel.innerHTML = `
            <div class="output-result output-error">
                <div class="result-header">
                    <strong>❌ Evaluation Error:</strong>
                </div>
                <pre>${result}</pre>
            </div>
        `;
        evaluationTimeElement.textContent = '';
    }
}

// Clear output
function clearOutput() {
    const outputPanel = document.getElementById('output-panel');
    outputPanel.innerHTML = `
        <div class="output-placeholder">
            <p>👈 Enter a policy and click "Evaluate" to see results</p>
        </div>
    `;
    document.getElementById('evaluation-time').textContent = '';
}

// Update status
function updateStatus(message, isError = false) {
    const statusText = document.getElementById('status-text');
    statusText.textContent = message;
    statusText.style.color = isError ? '#f48771' : '#cccccc';
}

// Coverage helper functions
function displayCoverage(coverageReport) {
    if (!coverageReport || !editors.policy) return;
    
    console.log('Coverage report:', coverageReport);
    const decorations = [];
    
    // Process coverage data - handle both array and object formats
    const files = Array.isArray(coverageReport.files) ? coverageReport.files : 
                  (coverageReport.files ? Object.values(coverageReport.files) : []);
    
    files.forEach(fileData => {
        if (fileData.path === 'playground.rego' || fileData.filename === 'playground.rego') {
            const covered = fileData.covered || {};
            
            // Handle both array of line numbers and object with line:count
            if (Array.isArray(covered)) {
                // Array format: [3, 5, 7] - lines that were covered
                covered.forEach(lineNumber => {
                    const range = new monaco.Range(lineNumber, 1, lineNumber, 1);
                    decorations.push({
                        range: range,
                        options: {
                            isWholeLine: true,
                            className: 'coverage-line-covered',
                            hoverMessage: { value: `Line ${lineNumber} was executed` }
                        }
                    });
                });
            } else {
                // Object format: {"3": 1, "5": 2} - line: hit count
                Object.entries(covered).forEach(([lineStr, hitCount]) => {
                    const lineNumber = parseInt(lineStr);
                    const range = new monaco.Range(lineNumber, 1, lineNumber, 1);
                    
                    let className = 'coverage-line-uncovered';
                    if (hitCount > 0) {
                        className = 'coverage-line-covered';
                    }
                    
                    decorations.push({
                        range: range,
                        options: {
                            isWholeLine: true,
                            className: className,
                            hoverMessage: { value: `Line executed ${hitCount} times` }
                        }
                    });
                });
            }
        }
    });
    
    console.log('Applying', decorations.length, 'coverage decorations');
    
    // Apply decorations
    coverageDecorations = editors.policy.deltaDecorations(coverageDecorations, decorations);
}

function clearCoverage() {
    if (editors.policy && coverageDecorations.length > 0) {
        coverageDecorations = editors.policy.deltaDecorations(coverageDecorations, []);
    }
    lastCoverageReport = null;
}

function getCoveredLinesCount() {
    if (!lastCoverageReport) return 0;
    let covered = 0;
    const files = Array.isArray(lastCoverageReport.files) ? lastCoverageReport.files : 
                  (lastCoverageReport.files ? Object.values(lastCoverageReport.files) : []);
    
    files.forEach(fileData => {
        const coveredData = fileData.covered || {};
        if (Array.isArray(coveredData)) {
            covered += coveredData.length;
        } else {
            Object.values(coveredData).forEach(hitCount => {
                if (hitCount > 0) covered++;
            });
        }
    });
    return covered;
}

function getTotalLinesCount() {
    if (!lastCoverageReport) return 0;
    let total = 0;
    const files = Array.isArray(lastCoverageReport.files) ? lastCoverageReport.files : 
                  (lastCoverageReport.files ? Object.values(lastCoverageReport.files) : []);
    
    files.forEach(fileData => {
        const coveredData = fileData.covered || {};
        if (Array.isArray(coveredData)) {
            // For array format, we need to get total lines from policy content
            // For now, use covered lines as approximation
            total += coveredData.length;
        } else {
            total += Object.keys(coveredData).length;
        }
    });
    return total;
}

function getCoveragePercentage() {
    const total = getTotalLinesCount();
    if (total === 0) return 0;
    return Math.round((getCoveredLinesCount() / total) * 100);
}

// Layout management
function changeLayout(layout) {
    const container = document.querySelector('.playground-container');
    const leftPanel = document.querySelector('.left-panel');
    const rightPanel = document.querySelector('.right-panel');
    
    // Remove existing layout classes
    container.classList.remove('layout-horizontal', 'layout-tabs', 'layout-policy-only', 'layout-fullscreen');
    
    switch (layout) {
        case 'split-horizontal':
            container.classList.add('layout-horizontal');
            leftPanel.style.display = 'flex';
            rightPanel.style.display = 'block';
            break;
        case 'split-vertical':
            // Default layout
            leftPanel.style.display = 'flex';
            rightPanel.style.display = 'block';
            break;
        case 'tabs':
            container.classList.add('layout-tabs');
            createTabLayout();
            break;
        case 'policy-only':
            container.classList.add('layout-policy-only');
            leftPanel.style.display = 'flex';
            rightPanel.style.display = 'none';
            break;
        case 'full-screen':
            container.classList.add('layout-fullscreen');
            leftPanel.style.display = 'flex';
            rightPanel.style.display = 'none';
            break;
    }
    
    // Trigger editor resize
    setTimeout(() => {
        Object.values(editors).forEach(editor => {
            if (editor && editor.layout) {
                editor.layout();
            }
        });
    }, 100);
}

function createTabLayout() {
    // For tabs layout, we'll show one editor at a time
    const editorSections = document.querySelectorAll('.editor-section');
    editorSections.forEach((section, index) => {
        section.style.display = index === 0 ? 'flex' : 'none';
    });
    
    // Add tab switching logic (simplified for now)
    console.log('Tab layout activated - click editor headers to switch');
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initPlayground);

// Handle window resize
window.addEventListener('resize', () => {
    if (editors.policy) editors.policy.layout();
    if (editors.input) editors.input.layout();
    if (editors.data) editors.data.layout();
});