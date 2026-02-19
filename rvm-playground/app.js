// RVM Playground Application

class RVMPlayground {
    constructor() {
        this.editors = {};
        this.wasmModule = null;
        this.currentProgram = null;
        this.debugSession = {
            active: false,
            started: false,
            vm: null,
            entryPoint: null,
            language: null
        };
        this.assemblyText = '';
        this.assemblyLineMap = new Map();
        this.activeAssemblyLine = null;
        this.policyDecorations = [];
        this.settings = {
            theme: 'vs',
            wordWrap: true,
            minimap: true,
            showAddresses: true,
            showComments: true,
            autoEvaluate: false
        };

        this.language = 'rego';
        this.languageState = {
            rego: {
                policy: '',
                input: '{}',
                data: '{}',
                entryPoints: ['data.authz.allow'],
                policyTitle: ''
            },
            cedar: {
                policy: '',
                input: '{}',
                entities: '{}',
                policyTitle: ''
                        },
                        azure: {
                                policy: '',
                                input: `{
    "resource": {
        "name": "example-vm",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "westus2",
        "sku": {
            "name": "Standard_D2s_v3"
        },
        "tags": {
            "costCenter": "cc-100"
        },
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                policyTitle: ''
            }
        };

                this.azureAliases = {
                        catalog: null,
                        aliasMap: {},
                        aliasesByType: {}
                };

        this.lastComparativeExampleName = localStorage.getItem('rvmPlaygroundLastComparative') || null;


        this.examples = {
            categories: {
                'Authorization': [
                    {
                        name: "Role-Based Access Control",
                        description: "Role-based permissions with resource patterns",
                        entryPoints: ["data.authz.allow"],
                        policy: `package authz

import rego.v1

# Allow only if a role grants the action for the resource pattern

default allow := false

allow if {
    user_has_permission(input.user.name, input.action, input.resource)
}

# Check if user has permission for action on resource
user_has_permission(user, action, resource) if {
    some role in input.user_roles[user]
    some permission in input.role_permissions[role]
    permission.action == action
    glob.match(permission.resource, [], resource)
}`,
                        input: `{
    "user": {"name": "alice", "id": "123"},
    "action": "read",
    "resource": "/api/users/123",
    "user_roles": {
        "alice": ["admin", "user"],
        "bob": ["user"],
        "charlie": ["viewer"]
    },
    "role_permissions": {
        "admin": [
            {"action": "read", "resource": "/api/*"},
            {"action": "write", "resource": "/api/*"},
            {"action": "delete", "resource": "/api/*"}
        ],
        "user": [
            {"action": "read", "resource": "/api/users/*"},
            {"action": "write", "resource": "/api/users/*"}
        ],
        "viewer": [
            {"action": "read", "resource": "/api/users/*"}
        ]
    }
}`,
                        data: '{}'
                    },
                    {
                        name: "Multi-Factor Authentication",
                        description: "MFA policy with time and device restrictions",
                        entryPoints: ["data.mfa.required", "data.mfa.allow"],
                        policy: `package mfa

import rego.v1

# Require MFA for sensitive actions, resources, or off-hours

default required := false
default allow := false

# MFA required for admin actions
required if {
    input.action in ["delete", "admin", "configure"]
}

# MFA required for sensitive resources
required if {
    startswith(input.resource, "/admin/")
}

# MFA required during off-hours
required if {
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour < 8
}
required if {
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour > 18
}

# Allow if MFA not required OR MFA verified
allow if not required
allow if {
    required
    input.mfa_verified == true
    device_trusted
}

device_trusted if {
    input.device_id in input.trusted_devices[input.user]
}`,
                        input: `{
    "user": "admin",
    "action": "delete",
    "resource": "/api/users/123",
    "mfa_verified": true,
    "device_id": "device_456",
    "trusted_devices": {
        "admin": ["device_123", "device_456"],
        "alice": ["device_789"]
    }
}`,
                        data: '{}'
                    }
                ],
                'Kubernetes': [
                    {
                        name: "Pod Security Standards",
                        description: "Kubernetes admission control for pod security",
                        entryPoints: ["data.kubernetes.admission.allow", "data.kubernetes.admission.violations"],
                        policy: `package kubernetes.admission

import rego.v1

# Reject pods that violate basic security constraints

default allow := false
default violations := []

# Allow if no violations
allow if count(violations) == 0

# Check for security violations
violations contains msg if {
    input.request.object.spec.containers[_].securityContext.privileged == true
    msg := "Privileged containers are not allowed"
}

violations contains msg if {
    input.request.object.spec.containers[_].securityContext.runAsRoot == true
    msg := "Containers cannot run as root"
}

violations contains msg if {
    container := input.request.object.spec.containers[_]
    not container.resources.limits.memory
    msg := sprintf("Container %s must specify memory limits", [container.name])
}

violations contains msg if {
    container := input.request.object.spec.containers[_]
    not container.resources.limits.cpu
    msg := sprintf("Container %s must specify CPU limits", [container.name])
}`,
                        input: `{
    "request": {
        "object": {
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "nginx:latest",
                        "securityContext": {
                            "privileged": false,
                            "runAsRoot": false
                        },
                        "resources": {
                            "limits": {
                                "memory": "128Mi",
                                "cpu": "100m"
                            }
                        }
                    }
                ]
            }
        }
    }
}`,
                        data: '{}'
                    },
                    {
                        name: "Network Policies",
                        description: "Kubernetes network security validation",
                        entryPoints: ["data.k8s.network.allow_ingress", "data.k8s.network.allow_egress"],
                        policy: `package k8s.network

import rego.v1

# Gate ingress/egress based on namespaces and ports

default allow_ingress := false
default allow_egress := false

# Allow ingress from same namespace
allow_ingress if {
    input.source.namespace == input.destination.namespace
}

# Allow ingress from specific allowed namespaces
allow_ingress if {
    input.source.namespace in input.allowed_namespaces[input.destination.namespace]
}

# Allow egress to public internet for specific ports
allow_egress if {
    input.destination.external == true
    input.port in [80, 443, 53]
}

# Allow egress to same cluster
allow_egress if {
    input.destination.external == false
    input.destination.cluster == input.source.cluster
}`,
                        input: `{
    "source": {
        "namespace": "frontend",
        "cluster": "prod-cluster"
    },
    "destination": {
        "namespace": "backend",
        "cluster": "prod-cluster",
        "external": false
    },
    "port": 8080,
    "allowed_namespaces": {
        "backend": ["frontend", "api-gateway"],
        "database": ["backend"]
    }
}`,
                        data: '{}'
                    }
                ],
                'Cloud': [
                    {
                        name: "AWS IAM Policy",
                        description: "Complex AWS IAM authorization",
                        entryPoints: ["data.aws.iam.allow"],
                        policy: `package aws.iam

import rego.v1

# Allow only when IAM-style checks pass (user, action, resource, conditions)

default allow := false

# Allow if all conditions are met
allow if {
    user_authenticated
    action_permitted
    resource_accessible
    conditions_met
}

# Check if user is authenticated
user_authenticated if {
    input.context.user.arn
    input.context.user.arn != ""
}

# Check if action is permitted
action_permitted if {
    some policy in input.policies[input.context.user.name]
    some statement in policy.Statement
    statement.Effect == "Allow"
    action_matches(statement.Action, input.request.action)
    resource_matches(statement.Resource, input.request.resource)
}

# Helper functions
action_matches(policy_action, request_action) if policy_action == "*"
action_matches(policy_action, request_action) if policy_action == request_action
action_matches(policy_action, request_action) if {
    endswith(policy_action, "*")
    startswith(request_action, trim_suffix(policy_action, "*"))
}

resource_matches(policy_resource, request_resource) if policy_resource == "*"
resource_matches(policy_resource, request_resource) if policy_resource == request_resource

resource_accessible if {
    region := extract_region(input.request.resource)
    region in input.allowed_regions
}

extract_region(arn) := region if {
    parts := split(arn, ":")
    count(parts) >= 4
    region := parts[3]
}

conditions_met if {
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour >= 9
    current_hour <= 17
}`,
                        input: `{
    "context": {
        "user": {
            "name": "alice",
            "arn": "arn:aws:iam::123456789012:user/alice"
        }
    },
    "request": {
        "action": "s3:GetObject",
        "resource": "arn:aws:s3:::my-bucket/data/file.txt"
    },
    "policies": {
        "alice": [
            {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "s3:*",
                        "Resource": "arn:aws:s3:::my-bucket/*"
                    }
                ]
            }
        ]
    },
    "allowed_regions": ["us-east-1", "us-west-2"]
}`,
                        data: '{}'
                    }
                ],
                'Business Logic': [
                    {
                        name: "Dynamic Pricing",
                        description: "Complex pricing rules with multiple discounts",
                        entryPoints: ["data.business.pricing.discount", "data.business.pricing.final_price"],
                        policy: `package business.pricing

import rego.v1

# Compute a discount and final price from multiple business rules

default discount := 0
default final_price := 0

# Calculate discount based on multiple factors
discount := calculated_discount if {
    calculated_discount := volume_discount + loyalty_discount + seasonal_discount
    calculated_discount <= 50  # Cap at 50%
}

discount := 50 if {
    calculated_discount := volume_discount + loyalty_discount + seasonal_discount
    calculated_discount > 50
}

# Volume-based discount
volume_discount := 0 if input.order.quantity < 10
volume_discount := 5 if {
    input.order.quantity >= 10
    input.order.quantity < 50
}
volume_discount := 10 if {
    input.order.quantity >= 50
    input.order.quantity < 100
}
volume_discount := 15 if input.order.quantity >= 100

# Loyalty discount
loyalty_discount := 0 if not input.customers[input.customer.id]
loyalty_discount := discount_rate if {
    customer := input.customers[input.customer.id]
    years := customer.years_active
    discount_rate := min(years * 2, 20)  # 2% per year, max 20%
}

# Seasonal discount
seasonal_discount := 10 if {
    current_month := time.clock([time.now_ns(), "UTC"])[1]
    current_month in [11, 12]  # November, December
}
seasonal_discount := 0 if {
    current_month := time.clock([time.now_ns(), "UTC"])[1]
    not current_month in [11, 12]
}

# Calculate final price
final_price := price_after_discount if {
    base_price := input.order.unit_price * input.order.quantity
    discount_amount := (base_price * discount) / 100
    price_after_discount := base_price - discount_amount
}`,
                        input: `{
    "customer": {"id": "cust_123"},
    "order": {
        "unit_price": 100,
        "quantity": 25,
        "product_id": "prod_456"
    },
    "customers": {
        "cust_123": {
            "name": "Acme Corp",
            "years_active": 5,
            "tier": "gold"
        }
    }
}`,
                        data: '{}'
                    },
                    {
                        name: "Approval Workflow",
                        description: "Multi-level approval system",
                        entryPoints: ["data.workflow.approval.required_approvers", "data.workflow.approval.can_approve"],
                        policy: `package workflow.approval

import rego.v1

# Determine required approvers and whether the current user can approve

default required_approvers := []
default can_approve := false

# Determine required approvers based on request value
required_approvers := ["manager"] if input.amount <= 1000
required_approvers := ["manager", "director"] if {
    input.amount > 1000
    input.amount <= 10000
}
required_approvers := ["manager", "director", "vp"] if input.amount > 10000

# Check if current user can approve this request
can_approve if {
    user_role := input.users[input.current_user].role
    user_role in required_approvers
    user_in_approval_chain
}

user_in_approval_chain if {
    user_dept := input.users[input.current_user].department
    request_dept := input.users[input.requester].department
    user_dept == request_dept
}

user_in_approval_chain if {
    input.users[input.current_user].role == "vp"  # VPs can approve across departments
}`,
                        input: `{
    "requester": "alice",
    "current_user": "manager_bob",
    "amount": 5000,
    "description": "New laptop purchase",
    "users": {
        "alice": {"role": "employee", "department": "engineering"},
        "manager_bob": {"role": "manager", "department": "engineering"},
        "director_charlie": {"role": "director", "department": "engineering"},
        "vp_diana": {"role": "vp", "department": "executive"}
    }
}`,
                        data: '{}'
                    }
                ],
                'Compilation': [
                    {
                        name: "Advanced Pattern Matching",
                        description: "Showcase various Rego compilation patterns",
                        entryPoints: ["data.compilation.patterns.analysis"],
                        policy: `package compilation.patterns

import rego.v1

# Showcase patterns: arrays, objects, strings, and comprehensions

default analysis := {}

# Demonstrate various Rego compilation patterns
analysis := {
    "array_patterns": array_analysis,
    "object_patterns": object_analysis,
    "string_patterns": string_analysis,
    "comprehensions": comprehension_analysis
}

# Array pattern matching and manipulation
array_analysis := {
    "filtered": [x | x := input.numbers[_]; x > 10],
    "mapped": [x * 2 | x := input.numbers[_]],
    "reduced": sum(input.numbers),
    "grouped": {
        "even": [x | x := input.numbers[_]; x % 2 == 0],
        "odd": [x | x := input.numbers[_]; x % 2 == 1]
    }
}

# Object pattern matching
object_analysis := {
    "nested_access": input.config.server.host,
    "conditional_fields": {k: v | 
        some k, v in input.metadata
        is_string(v)
        count(v) > 5
    },
    "transformed": {k: upper(v) | 
        some k, v in input.labels
        is_string(v)
    }
}

# String pattern matching and regex
string_analysis := {
    "email_domains": {domain |
        some user in input.users
        regex.match(\`^[^@]+@(.+)$\`, user.email)
        domain := regex.find_n(\`^[^@]+@(.+)$\`, user.email, 1)[0][1]
    },
    "valid_usernames": [user.name |
        some user in input.users
        regex.match(\`^[a-zA-Z][a-zA-Z0-9_]{2,19}$\`, user.name)
    ]
}

# Complex comprehensions
comprehension_analysis := {
    "nested_loop": [
        {"user": user.name, "permission": perm, "resource": res} |
        some user in input.users
        some perm in user.permissions
        some res in input.resources[perm]
    ],
    "conditional_aggregation": {
        dept: {
            "count": count(users),
            "avg_salary": sum([u.salary | u := users[_]]) / count(users)
        } |
        some dept, users in grouped_users
        count(users) > 0
    }
}

# Helper rule for grouping
grouped_users[dept] := users if {
    some dept
    users := [u | some u in input.users; u.department == dept]
}`,
                        input: `{
    "numbers": [1, 5, 10, 15, 20, 25],
    "config": {
        "server": {"host": "localhost", "port": 8080}
    },
    "metadata": {
        "version": "1.0.0",
        "name": "test-app",
        "description": "A comprehensive test application"
    },
    "labels": {
        "env": "production",
        "team": "platform"
    },
    "users": [
        {"name": "alice123", "email": "alice@company.com", "department": "engineering", "salary": 120000, "permissions": ["read", "write"]},
        {"name": "bob_dev", "email": "bob@company.com", "department": "engineering", "salary": 115000, "permissions": ["read"]},
        {"name": "charlie", "email": "charlie@company.com", "department": "sales", "salary": 95000, "permissions": ["read", "admin"]}
    ],
    "resources": {
        "read": ["/api/users", "/api/data"],
        "write": ["/api/users"],
        "admin": ["/api/admin", "/api/config"]
    }
}`,
                        data: '{}'
                    },
                    {
                        name: "Complex Rule Dependencies",
                        description: "Demonstrate complex rule interdependencies and optimization",
                        entryPoints: ["data.complex.rules.final_decision"],
                        policy: `package complex.rules

import rego.v1

# Combine multiple signals into a single authorization decision

default final_decision := {}

# Complex decision making with multiple interdependent rules
final_decision := {
    "allowed": allowed,
    "risk_level": risk_level,
    "required_actions": required_actions,
    "metadata": decision_metadata
}

# Main authorization logic
allowed if {
    not high_risk_user
    not suspicious_activity
    valid_time_window
    resource_available
}

# Risk assessment
risk_level := "high" if high_risk_user
risk_level := "medium" if {
    not high_risk_user
    suspicious_activity
}
risk_level := "low" if {
    not high_risk_user
    not suspicious_activity
}

# High risk user determination
high_risk_user if {
    failed_logins_count > 5
}

high_risk_user if {
    input.user.id in input.blocked_users
}

high_risk_user if {
    geo_anomaly
}

# Suspicious activity detection
suspicious_activity if unusual_access_pattern
suspicious_activity if rapid_requests
suspicious_activity if privilege_escalation_attempt

# Helper rules
failed_logins_count := count([l | l := input.login_attempts[input.user.id][_]; l.status == "failed"])

geo_anomaly if {
    user_location := input.context.geo.country
    usual_locations := {l | l := input.user_locations[input.user.id][_]}
    not user_location in usual_locations
}

unusual_access_pattern if {
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour < 6
    current_hour > 22
}

rapid_requests if {
    recent_requests := [r | r := input.recent_requests[input.user.id][_]; r.timestamp > time.now_ns() - 300000000000]  # 5 minutes
    count(recent_requests) > 100
}

privilege_escalation_attempt if {
    input.requested_permissions[_] in ["admin", "super_admin"]
    not input.user.role in ["admin", "super_admin"]
}

valid_time_window if {
    current_hour := time.clock([time.now_ns(), "UTC"])[0]
    current_hour >= input.business_hours.start
    current_hour <= input.business_hours.end
}

resource_available if {
    not input.resource.id in input.maintenance_resources
}

# Required actions based on decision
required_actions contains "mfa_verification" if {
    allowed
    risk_level in ["medium", "high"]
}

required_actions contains "manager_approval" if {
    allowed
    privilege_escalation_attempt
}

required_actions contains "security_review" if high_risk_user

# Decision metadata
decision_metadata := {
    "timestamp": time.now_ns(),
    "factors": {
        "high_risk_user": high_risk_user,
        "suspicious_activity": suspicious_activity,
        "failed_logins": failed_logins_count,
        "geo_anomaly": geo_anomaly
    }
}`,
                        input: `{
    "user": {"id": "user123", "role": "user"},
    "resource": {"id": "resource456", "type": "document"},
    "context": {"geo": {"country": "US"}},
    "requested_permissions": ["read", "write"],
    "blocked_users": ["baduser1", "baduser2"],
    "login_attempts": {
        "user123": [
            {"timestamp": 1630000000, "status": "success"},
            {"timestamp": 1630000060, "status": "failed"}
        ]
    },
    "user_locations": {
        "user123": ["US", "CA"]
    },
    "recent_requests": {
        "user123": [
            {"timestamp": 1630000000000000000, "endpoint": "/api/data"}
        ]
    },
    "business_hours": {
        "start": 9,
        "end": 17
    },
    "maintenance_resources": ["resource999"]
}`,
                        data: '{}'
                    }
                ]
            },
            policies: [] // Legacy flat array for compatibility
        };

        this.cedarExamples = {
            categories: {
                'Cedar Basics': [
                    {
                        name: "Budget View",
                        description: "Permit admins from internal IPs",
                        policy: `// Permit admins from internal IPs to view the budget file
permit(
    principal in User::"admins",
    action == Action::"view",
    resource == File::"budget"
)
when {
    context has ip &&
    context.ip like "10.*"
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::view",
    "resource": "File::budget",
    "context": {"ip": "10.1.2.3"}
}`,
                        entities: `{
    "User::alice": {
        "parents": ["User::admins"],
        "attrs": {"department": "finance"}
    },
    "User::admins": {
        "parents": [],
        "attrs": {}
    }
}`,
                        language: 'cedar'
                    },
                    {
                        name: "Owner Edit",
                        description: "Allow resource owners to edit",
                        policy: `// Allow owners to edit their own draft
permit(
    principal,
    action == Action::"edit",
    resource == Doc::"draft"
)
when {
    resource has owner &&
    principal == resource.owner
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::edit",
    "resource": "Doc::draft",
    "context": {}
}`,
                        entities: `{
    "Doc::draft": {
        "parents": [],
        "attrs": {"owner": "User::alice"}
    }
}`,
                        language: 'cedar'
                    }
                ]
            }
        };

                this.azureExamples = {
                        categories: {
                                'Azure Policy': [
                                        {
                                                name: "Require Cost Center Tag",
                                                description: "Deny resources missing a costCenter tag",
                                                policy: `{
    "properties": {
        "displayName": "Require costCenter tag",
        "policyType": "Custom",
        "mode": "Indexed",
        "description": "Require a costCenter tag on resources.",
        "metadata": {
            "version": "1.0.0",
            "category": "Tags"
        },
        "version": "1.0.0",
        "parameters": {
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "tags.costCenter",
                "exists": "false"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/require-costcenter-tag",
    "name": "require-costcenter-tag",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "storage-dev",
        "type": "Microsoft.Storage/storageAccounts",
        "location": "westus2",
        "tags": {
            "owner": "team-a"
        },
        "properties": {
            "supportsHttpsTrafficOnly": true
        }
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        },
                                        {
                                                name: "Allowed Locations",
                                                description: "Restrict deployments to approved regions",
                                                policy: `{
    "properties": {
        "displayName": "Allowed locations",
        "policyType": "Custom",
        "mode": "Indexed",
        "description": "Restrict deployments to approved regions.",
        "metadata": {
            "version": "1.0.0",
            "category": "General"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedLocations": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed locations",
                    "description": "The list of permitted locations"
                },
                "defaultValue": ["westus2", "eastus"]
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "location",
                "notIn": "[parameters('allowedLocations')]"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/allowed-locations",
    "name": "allowed-locations",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "vm-east",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "centralus",
        "sku": {
            "name": "Standard_D2s_v3"
        },
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        },
                                        {
                                                name: "VM SKU Allowlist",
                                                description: "Deny disallowed VM SKUs",
                                                policy: `{
    "properties": {
        "displayName": "Allowed VM SKUs",
        "policyType": "Custom",
        "mode": "All",
        "description": "Restrict virtual machine sizes to approved SKUs.",
        "metadata": {
            "version": "1.0.0",
            "category": "Compute"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedSkus": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed VM SKUs",
                    "description": "List of approved virtual machine sizes"
                },
                "defaultValue": ["Standard_D2s_v3", "Standard_D4s_v3"]
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "Microsoft.Compute/virtualMachines/sku.name",
                "notIn": "[parameters('allowedSkus')]"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/allowed-vm-skus",
    "name": "allowed-vm-skus",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "vm-sku-test",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "westus2",
        "sku": {
            "name": "Standard_B1s"
        },
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        },
                                        {
                                                name: "Storage IP Allowlist (count/where)",
                                                description: "Deny storage accounts with unapproved allowed IPs",
                                                policy: `{
    "properties": {
        "displayName": "Storage IP allowlist",
        "policyType": "Custom",
        "mode": "Indexed",
        "description": "Only allow IP rules that match an approved allowlist.",
        "metadata": {
            "version": "1.0.0",
            "category": "Network"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedIps": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed IPs",
                    "description": "IP addresses permitted in IP rules"
                },
                "defaultValue": ["10.0.0.0/24", "192.168.10.10"]
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "count": {
                    "field": "Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]",
                    "where": {
                        "allOf": [
                            {
                                "field": "Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].action",
                                "equals": "Allow"
                            },
                            {
                                "field": "Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value",
                                "notIn": "[parameters('allowedIps')]"
                            }
                        ]
                    }
                },
                "greater": 0
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/storage-ip-allowlist",
    "name": "storage-ip-allowlist",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "storage-dev",
        "type": "Microsoft.Storage/storageAccounts",
        "location": "westus2",
        "properties": {
            "networkAcls": {
                "ipRules": [
                    {"value": "10.0.0.0/24", "action": "Allow"},
                    {"value": "203.0.113.5", "action": "Allow"}
                ]
            }
        }
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        },
                                        {
                                                name: "Tag + Location + SKU Guard",
                                                description: "AnyOf with tag, location, and SKU constraints",
                                                policy: `{
    "properties": {
        "displayName": "Tag, location, and SKU guard",
        "policyType": "Custom",
        "mode": "All",
        "description": "Require environment tag, allowed location, and approved VM SKU family.",
        "metadata": {
            "version": "1.0.0",
            "category": "General"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedLocations": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed locations",
                    "description": "Locations permitted for deployment"
                },
                "defaultValue": ["westus2", "eastus"]
            },
            "allowedSkuPattern": {
                "type": "String",
                "metadata": {
                    "displayName": "Allowed SKU pattern",
                    "description": "VM SKU pattern that is permitted"
                },
                "defaultValue": "Standard_D*"
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "anyOf": [
                    {
                        "not": {
                            "field": "tags",
                            "containsKey": "environment"
                        }
                    },
                    {
                        "field": "location",
                        "notIn": "[parameters('allowedLocations')]"
                    },
                    {
                        "allOf": [
                            {
                                "field": "type",
                                "equals": "Microsoft.Compute/virtualMachines"
                            },
                            {
                                "field": "Microsoft.Compute/virtualMachines/sku.name",
                                "notLike": "[parameters('allowedSkuPattern')]"
                            }
                        ]
                    }
                ]
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/tag-location-sku-guard",
    "name": "tag-location-sku-guard",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "vm-legacy",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "centralus",
        "sku": {
            "name": "Standard_B1s"
        },
        "tags": {
            "owner": "team-a"
        },
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        },
                                        {
                                                name: "Naming Convention Prefix",
                                                description: "Enforce a name prefix using template expressions",
                                                policy: `{
    "properties": {
        "displayName": "Naming convention prefix",
        "policyType": "Custom",
        "mode": "All",
        "description": "Require resource names to start with a configurable prefix.",
        "metadata": {
            "version": "1.0.0",
            "category": "General"
        },
        "version": "1.0.0",
        "parameters": {
            "namePrefix": {
                "type": "String",
                "metadata": {
                    "displayName": "Name prefix",
                    "description": "Prefix that resource names must start with"
                },
                "defaultValue": "prod"
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "value": "[substring(tolower(field('name')), 0, 4)]",
                "notEquals": "[tolower(parameters('namePrefix'))]"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/name-prefix",
    "name": "name-prefix",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "dev-app-01",
        "type": "Microsoft.Web/sites",
        "location": "eastus",
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        }
                                ]
                        }
                };

        this.comparativeExamples = [
                        {
                                name: "Required Tag",
                            description: "Deny resources missing a costCenter tag",
                                variants: {
                                        rego: {
                                                policy: `package tags

import rego.v1

default allow := false

allow if {
        input.resource.tags.costCenter
}`,
                                                input: `{
        "resource": {
        "tags": {
            "owner": "team-a"
        }
        }
}`,
                                                data: '{}',
                                                entryPoints: ["data.tags.allow"],
                                                language: 'rego'
                                        },
                                        cedar: {
                        policy: `// Permit when the resource has a costCenter

permit(
    principal,
    action == Action::"use",
    resource == Resource::"demo"
)
when {
    resource has costCenter &&
    resource.costCenter != ""
};`,
                                                input: `{
        "principal": "User::alice",
        "action": "Action::use",
        "resource": "Resource::demo",
        "context": {}
}`,
                                                entities: `{
        "Resource::demo": {
                "parents": [],
        "attrs": {"owner": "team-a"}
        }
}`,
                                                language: 'cedar'
                                        },
                                        azure: {
                                                policy: `{
    "properties": {
        "displayName": "Require costCenter tag",
        "policyType": "Custom",
        "mode": "Indexed",
        "description": "Require a costCenter tag on resources.",
        "metadata": {
            "version": "1.0.0",
            "category": "Tags"
        },
        "version": "1.0.0",
        "parameters": {
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "tags.costCenter",
                "exists": "false"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/require-costcenter-tag",
    "name": "require-costcenter-tag",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "storage-dev",
        "type": "Microsoft.Storage/storageAccounts",
        "location": "westus2",
        "tags": {
            "owner": "team-a"
        },
        "properties": {
            "supportsHttpsTrafficOnly": true
        }
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        }
                                }
                        },
                        {
                                name: "Allowed Locations",
                                description: "Deny locations outside the approved list",
                                variants: {
                                        rego: {
                                                policy: `package locations

import rego.v1

default allow := false

allow if {
        input.resource.location in ["westus2", "eastus"]
}`,
                                                input: `{
        "resource": {
        "location": "centralus"
        }
}`,
                                                data: '{}',
                                                entryPoints: ["data.locations.allow"],
                                                language: 'rego'
                                        },
                                        cedar: {
                        policy: `// Permit when location is approved

permit(
    principal,
    action == Action::"deploy",
    resource == Resource::"demo"
)
when {
    context has allowedLocations &&
    resource has location &&
    context.allowedLocations.contains(resource.location)
};`,
                                                input: `{
        "principal": "User::alice",
        "action": "Action::deploy",
        "resource": "Resource::demo",
        "context": {"allowedLocations": ["westus2", "eastus"]}
}`,
                                                entities: `{
        "Resource::demo": {
                "parents": [],
        "attrs": {"location": "centralus"}
        }
}`,
                                                language: 'cedar'
                                        },
                                        azure: {
                                                policy: `{
    "properties": {
        "displayName": "Allowed locations",
        "policyType": "Custom",
        "mode": "Indexed",
        "description": "Restrict deployments to approved regions.",
        "metadata": {
            "version": "1.0.0",
            "category": "General"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedLocations": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed locations",
                    "description": "The list of permitted locations"
                },
                "defaultValue": ["westus2", "eastus"]
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "location",
                "notIn": "[parameters('allowedLocations')]"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/allowed-locations",
    "name": "allowed-locations",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "vm-east",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "centralus",
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        }
                                }
                        },
                        {
                                name: "VM SKU Allowlist",
                                description: "Deny disallowed VM SKUs",
                                variants: {
                                        rego: {
                                                policy: `package vm.sku

import rego.v1

default allow := false

allow if {
        input.resource.sku in ["Standard_D2s_v3", "Standard_D4s_v3"]
}`,
                                                input: `{
        "resource": {
        "sku": "Standard_B1s"
        }
}`,
                                                data: '{}',
                                                entryPoints: ["data.vm.sku.allow"],
                                                language: 'rego'
                                        },
                                        cedar: {
                        policy: `// Permit when SKU is allowed

permit(
    principal,
    action == Action::"deploy",
    resource == Resource::"demo"
)
when {
    context has allowedSkus &&
    resource has sku &&
    context.allowedSkus.contains(resource.sku)
};`,
                                                input: `{
        "principal": "User::alice",
        "action": "Action::deploy",
        "resource": "Resource::demo",
        "context": {"allowedSkus": ["Standard_D2s_v3", "Standard_D4s_v3"]}
}`,
                                                entities: `{
        "Resource::demo": {
                "parents": [],
        "attrs": {"sku": "Standard_B1s"}
        }
}`,
                                                language: 'cedar'
                                        },
                                        azure: {
                                                policy: `{
    "properties": {
        "displayName": "Allowed VM SKUs",
        "policyType": "Custom",
        "mode": "All",
        "description": "Restrict virtual machine sizes to approved SKUs.",
        "metadata": {
            "version": "1.0.0",
            "category": "Compute"
        },
        "version": "1.0.0",
        "parameters": {
            "allowedSkus": {
                "type": "Array",
                "metadata": {
                    "displayName": "Allowed VM SKUs",
                    "description": "List of approved virtual machine sizes"
                },
                "defaultValue": ["Standard_D2s_v3", "Standard_D4s_v3"]
            },
            "effect": {
                "type": "String",
                "metadata": {
                    "displayName": "Effect",
                    "description": "Enable or disable the execution of the policy"
                },
                "allowedValues": ["deny", "audit", "disabled"],
                "defaultValue": "deny"
            }
        },
        "policyRule": {
            "if": {
                "field": "Microsoft.Compute/virtualMachines/sku.name",
                "notIn": "[parameters('allowedSkus')]"
            },
            "then": {
                "effect": "[parameters('effect')]"
            }
        },
        "versions": ["1.0.0"]
    },
    "id": "/providers/Microsoft.Authorization/policyDefinitions/allowed-vm-skus",
    "name": "allowed-vm-skus",
    "type": "Microsoft.Authorization/policyDefinitions"
}`,
                                                input: `{
    "resource": {
        "name": "vm-sku-test",
        "type": "Microsoft.Compute/virtualMachines",
        "location": "westus2",
        "sku": {
            "name": "Standard_B1s"
        },
        "properties": {}
    },
    "context": {},
    "parameters": {}
}`,
                                                language: 'azure'
                                        }
                                }
                        },
            {
                name: "Owner Edit",
                description: "Same owner check expressed in two languages",
                variants: {
                    rego: {
                        policy: `package doc.authz

import rego.v1

# Allow only when the caller owns the document

default allow := false

allow if {
    input.action == "edit"
    input.principal == input.resource.owner
}`,
                        input: `{
    "principal": "User::alice",
    "action": "edit",
    "resource": {"id": "Doc::draft", "owner": "User::alice"}
}`,
                        data: '{}',
                        entryPoints: ["data.doc.authz.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Allow only when the caller owns the document

permit(
    principal,
    action == Action::"edit",
    resource == Doc::"draft"
)
when {
    resource has owner &&
    principal == resource.owner
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::edit",
    "resource": "Doc::draft",
    "context": {}
}`,
                        entities: `{
    "Doc::draft": {
        "parents": [],
        "attrs": {"owner": "User::alice"}
    }
}`,
                        language: 'cedar'
                    }
                }
            },
            {
                name: "IAM Allow",
                description: "Basic IAM-style allow rule with action + resource",
                variants: {
                    rego: {
                        policy: `package iam.authz

import rego.v1

# IAM-style allow: action + bucket + object key + principal list

default allow := false

allow if {
    input.action == "s3:GetObject"
    input.resource.bucket == "my-bucket"
    startswith(input.resource.key, "data/")
    input.principal in input.allowed_principals
}
`,
                        input: `{
    "principal": "User::alice",
    "action": "s3:GetObject",
    "resource": {"bucket": "my-bucket", "key": "data/report.csv"},
    "allowed_principals": ["User::alice", "User::ops"]
}`,
                        data: '{}',
                        entryPoints: ["data.iam.authz.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Allow get-object in the bucket for approved principals

permit(
    principal,
    action == Action::"s3:GetObject",
    resource == Resource::"my-bucket"
)
when {
    principal in User::"allowed" &&
    context has object_key &&
    context.object_key like "data/*"
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::s3:GetObject",
    "resource": "Resource::my-bucket",
    "context": {"object_key": "data/report.csv"}
}`,
                        entities: `{
    "User::alice": {
        "parents": ["User::allowed"],
        "attrs": {}
    },
    "User::allowed": {
        "parents": [],
        "attrs": {}
    },
    "Resource::my-bucket": {
        "parents": [],
        "attrs": {"type": "s3-bucket"}
    }
}`,
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Kubernetes Admission",
                description: "Simple privileged container check",
                variants: {
                    rego: {
                        policy: `package k8s.admission

import rego.v1

# Allow only non-privileged pods

default allow := false

allow if {
    not input.pod.privileged
}`,
                        input: `{
    "pod": {
        "name": "web",
        "privileged": false
    }
}`,
                        data: '{}',
                        entryPoints: ["data.k8s.admission.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Admit pod only when it is not privileged

permit(
    principal,
    action == Action::"create",
    resource == Pod::"web"
)
when {
    resource has privileged &&
    !resource.privileged
};`,
                        input: `{
    "principal": "User::admission",
    "action": "Action::create",
    "resource": "Pod::web",
    "context": {}
}`,
                        entities: `{
    "Pod::web": {
        "parents": [],
        "attrs": {"privileged": false}
    }
}`,
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Time Window Access",
                description: "Permit only during business hours",
                variants: {
                    rego: {
                        policy: `package access.window

import rego.v1

# Allow only during business hours from input context

default allow := false

allow if {
    hour := input.context.hour
    hour >= 9
    hour < 18
}`,
                        input: `{
    "context": {"hour": 10}
}`,
                        data: '{}',
                        entryPoints: ["data.access.window.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Permit access only during a time window in context

permit(
    principal,
    action == Action::"access",
    resource == Door::"lab"
)
when {
    context has hour &&
    context.hour >= 9 &&
    context.hour < 18
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::access",
    "resource": "Door::lab",
    "context": {"hour": 10}
}`,
                        entities: '{}',
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Attribute Match",
                description: "Allow if request country matches resource region",
                variants: {
                    rego: {
                        policy: `package geo.match

import rego.v1

# Allow only when request country matches resource region

default allow := false

allow if {
    input.request.country == input.resource.region
}`,
                        input: `{
    "request": {"country": "US"},
    "resource": {"id": "db-1", "region": "US"}
}`,
                        data: '{}',
                        entryPoints: ["data.geo.match.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Allow read when request country matches resource region

permit(
    principal,
    action == Action::"read",
    resource == Database::"db-1"
)
when {
    context has country &&
    resource has region &&
    context.country == resource.region
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::read",
    "resource": "Database::db-1",
    "context": {"country": "US"}
}`,
                        entities: `{
    "Database::db-1": {"parents": [], "attrs": {"region": "US"}}
}`,
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Dual Approval",
                description: "Require two approvals before release",
                variants: {
                    rego: {
                        policy: `package approvals

import rego.v1

# Require manager and security approvals

default allow := false

allow if {
    count(input.approvals) >= 2
    "manager" in input.approvals
    "security" in input.approvals
}`,
                        input: `{
    "approvals": ["manager", "security"]
}`,
                        data: '{}',
                        entryPoints: ["data.approvals.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Permit release only when both approvals are present

permit(
    principal,
    action == Action::"release",
    resource == Build::"candidate"
)
when {
    context has approvals &&
    context.approvals.contains("manager") &&
    context.approvals.contains("security")
};`,
                        input: `{
    "principal": "User::release-bot",
    "action": "Action::release",
    "resource": "Build::candidate",
    "context": {"approvals": ["manager", "security"]}
}`,
                        entities: '{}',
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Quotas and Budget",
                description: "Block if monthly spend exceeds limit",
                variants: {
                    rego: {
                        policy: `package budget

import rego.v1

# Block requests that exceed the remaining budget

default allow := false

allow if {
    input.monthly_spend + input.request_cost <= input.budget_limit
}`,
                        input: `{
    "monthly_spend": 4200,
    "request_cost": 500,
    "budget_limit": 5000
}`,
                        data: '{}',
                        entryPoints: ["data.budget.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Permit purchase when spend stays within the budget limit

permit(
    principal,
    action == Action::"purchase",
    resource == Budget::"team"
)
when {
    resource has limit &&
    context has monthly_spend &&
    context has request_cost &&
    context.monthly_spend + context.request_cost <= resource.limit
};`,
                        input: `{
    "principal": "User::alice",
    "action": "Action::purchase",
    "resource": "Budget::team",
    "context": {"monthly_spend": 4200, "request_cost": 500}
}`,
                        entities: `{
    "Budget::team": {"parents": [], "attrs": {"limit": 5000}}
}`,
                        language: 'cedar'
                    }
                }
            },
            {
                name: "Scoped Delegation",
                description: "Allow delegate only for specific project",
                variants: {
                    rego: {
                        policy: `package delegation

import rego.v1

# Allow owners or delegates for the alpha project

default allow := false

allow if {
    input.actor == input.resource.owner
}

allow if {
    input.actor in input.delegates[input.resource.owner]
    input.resource.project == "alpha"
}`,
                        input: `{
    "actor": "User::bob",
    "resource": {"id": "doc-7", "owner": "User::alice", "project": "alpha"},
    "delegates": {"User::alice": ["User::bob"]}
}`,
                        data: '{}',
                        entryPoints: ["data.delegation.allow"],
                        language: 'rego'
                    },
                    cedar: {
                        policy: `// Permit owner or delegate for project alpha

permit(
    principal,
    action == Action::"edit",
    resource == Doc::"doc-7"
)
when {
    resource has owner &&
    principal == resource.owner
};

permit(
    principal,
    action == Action::"edit",
    resource == Doc::"doc-7"
)
when {
    resource has delegates &&
    resource has project &&
    principal in resource.delegates &&
    resource.project == "alpha"
};`,
                        input: `{
    "principal": "User::bob",
    "action": "Action::edit",
    "resource": "Doc::doc-7",
    "context": {}
}`,
                        entities: `{
    "Doc::doc-7": {
        "parents": [],
        "attrs": {"owner": "User::alice", "project": "alpha", "delegates": ["User::bob"]}
    }
}`,
                        language: 'cedar'
                    }
                }
            }
        ];
        
        this.init();
    }

    async init() {
        this.updateStatus('Initializing Monaco Editor...');
        await this.initMonaco();

        this.setupEventListeners();
        this.loadSettings();
        this.loadLanguagePreference();

        this.updateStatus('Loading WASM module...');
        try {
            await this.loadWASM();
        } catch (error) {
            this.updateStatus('WASM module failed to load (UI available)');
        }

        await this.loadAzureAliases();

        // Load last-selected example (or default) for the active language
        this.loadInitialExampleForLanguage();

        if (this.isWasmLoaded) {
            this.updateStatus('Ready');
        }
    }

    async initMonaco() {
        return new Promise((resolve) => {
            require.config({ paths: { vs: 'https://unpkg.com/monaco-editor@0.44.0/min/vs' } });
            require(['vs/editor/editor.main'], () => {
                this.setupMonacoEditors();
                resolve();
            });
        });
    }

    setupMonacoEditors() {
        // Register Rego language
        monaco.languages.register({ id: 'rego' });
        monaco.languages.register({ id: 'cedar' });

        // Define Rego syntax highlighting
        monaco.languages.setMonarchTokensProvider('rego', {
            tokenizer: {
                root: [
                    [/\b(package|import|as|default|if|else|not|some|every|with)\b/, 'keyword'],
                    [/\b(true|false|null)\b/, 'constant'],
                    [/\b\d+(\.\d+)?\b/, 'number'],
                    [/"([^"\\]|\\.)*"/, 'string'],
                    [/`([^`\\]|\\.)*`/, 'string'],
                    [/#.*$/, 'comment'],
                    [/[{}\[\]()]/, 'bracket'],
                    [/[<>]=?|[!=]=?|&&|\|\||\+|-|\*|\/|%/, 'operator'],
                    [/[a-zA-Z_][a-zA-Z0-9_]*/, 'identifier']
                ]
            }
        });

        // Define Cedar syntax highlighting
        monaco.languages.setMonarchTokensProvider('cedar', {
            keywords: [
                'permit', 'forbid', 'when', 'unless', 'in', 'like', 'has', 'is', 'contains'
            ],
            booleans: ['true', 'false'],
            cedarFields: ['principal', 'resource', 'action', 'context', 'this'],
            tokenizer: {
                root: [
                    { include: '@whitespace' },
                    [/[{}\[\]()]/, 'bracket'],
                    [/[<>]=?|[!=]=?|&&|\|\||\+|-|\*|\/|%/, 'operator'],
                    [/\b\d+(\.\d+)?\b/, 'number'],
                    [/"([^"\\]|\\.)*"/, 'string'],
                    [/[a-zA-Z_][a-zA-Z0-9_]*::[a-zA-Z_"0-9:.-]+/, 'type.identifier'],
                    [/[a-zA-Z_][a-zA-Z0-9_]*/, {
                        cases: {
                            '@keywords': 'keyword',
                            '@booleans': 'constant',
                            '@cedarFields': 'variable.predefined',
                            '@default': 'identifier'
                        }
                    }]
                ],
                whitespace: [
                    [/[ \t\r\n]+/, 'white'],
                    [/\/\/.*$/, 'comment']
                ]
            }
        });

        // Setup policy editor
        this.editors.policy = monaco.editor.create(document.getElementById('policy-editor'), {
            value: '',
            language: this.getPolicyEditorLanguageId(),
            theme: this.settings.theme,
            wordWrap: this.settings.wordWrap ? 'on' : 'off',
            minimap: { enabled: this.settings.minimap },
            fontSize: 14,
            lineNumbers: 'on',
            roundedSelection: false,
            scrollBeyondLastLine: false,
            automaticLayout: true
        });

        // Setup input editor (JSON)
        this.editors.input = monaco.editor.create(document.getElementById('input-editor'), {
            value: '{}',
            language: 'json',
            theme: this.settings.theme,
            wordWrap: this.settings.wordWrap ? 'on' : 'off',
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbers: 'on',
            automaticLayout: true
        });

        // Setup data editor (JSON)
        this.editors.data = monaco.editor.create(document.getElementById('data-editor'), {
            value: '{}',
            language: 'json',
            theme: this.settings.theme,
            wordWrap: this.settings.wordWrap ? 'on' : 'off',
            minimap: { enabled: false },
            fontSize: 13,
            lineNumbers: 'on',
            automaticLayout: true
        });

        // Add change listeners
        this.editors.policy.onDidChangeModelContent(() => {
            if (this.settings.autoEvaluate) {
                this.debounce(() => this.compile(), 1000);
            }
        });

        this.editors.input.onDidChangeModelContent(() => {
            if (this.settings.autoEvaluate) {
                this.debounce(() => this.evaluate(), 500);
            }
        });

        this.editors.data.onDidChangeModelContent(() => {
            if (this.settings.autoEvaluate) {
                this.debounce(() => this.evaluate(), 500);
            }
        });
    }

    async loadWASM() {
        try {
            this.updateStatus('Loading WASM module...');
            
            // Import the real WASM module
            const wasmModule = await import('./wasm/regorusjs.js');
            await wasmModule.default();
            
            // Import the classes and functions we need
            const { Program, Rvm } = wasmModule;

            this.wasmModule = {
                Program,
                Rvm
            };
            
            this.updateStatus('WASM module loaded successfully');
            this.updateVMStatus('Loaded');
            this.isWasmLoaded = true;
            
        } catch (error) {
            console.error('Failed to load WASM module:', error);
            const errorMessage = error.message || error.toString() || 'Unknown WASM loading error';
            this.updateStatus(`Failed to load WASM module: ${errorMessage}`);
            this.updateVMStatus('Load failed');
            throw error;
        }
    }

    async loadAzureAliases() {
        try {
            const response = await fetch('./azure-policy-aliases.json', { cache: 'force-cache' });
            if (!response.ok) {
                throw new Error(`alias catalog fetch failed (${response.status})`);
            }
            const catalog = await response.json();
            this.azureAliases.catalog = catalog;
            this.azureAliases.aliasMap = this.buildAzureAliasMap(catalog);
            this.azureAliases.aliasesByType = this.buildAzureAliasIndex(catalog);
        } catch (error) {
            console.warn('Azure alias catalog unavailable:', error);
            this.azureAliases.catalog = null;
            this.azureAliases.aliasMap = {};
            this.azureAliases.aliasesByType = {};
        }
    }

    setupEventListeners() {
        // Header buttons
        document.getElementById('compile-btn').addEventListener('click', () => this.compile());
        document.getElementById('evaluate-btn').addEventListener('click', () => this.evaluate());
        document.getElementById('settings-btn').addEventListener('click', () => this.showSettings());
        document.getElementById('language-select').addEventListener('change', (e) => {
            this.setLanguage(e.target.value);
        });
        
        // Panel actions
        document.getElementById('policy-examples-btn').addEventListener('click', () => this.showExamples('policies'));
        document.getElementById('policy-clear-btn').addEventListener('click', () => this.clearPolicy());
        document.getElementById('debug-step-btn').addEventListener('click', () => this.debugStep());
        document.getElementById('debug-reset-btn').addEventListener('click', () => this.resetDebugSession());
        
        document.getElementById('assembly-copy-btn').addEventListener('click', () => this.copyAssembly());
        document.getElementById('assembly-format').addEventListener('change', (e) => {
            this.settings.assemblyFormat = e.target.value;
            this.refreshAssembly();
        });
        
        document.getElementById('data-examples-btn').addEventListener('click', () => this.showExamples('data'));
        
        // Tab switching
        document.querySelectorAll('.tab-button').forEach(button => {
            button.addEventListener('click', (e) => {
                const tab = e.target.dataset.tab;
                this.switchTab(tab);
            });
        });
        
        // Modal handling
        document.querySelectorAll('.modal-close').forEach(close => {
            close.addEventListener('click', (e) => {
                e.target.closest('.modal').classList.remove('show');
            });
        });
        
        // Click outside modal to close
        document.querySelectorAll('.modal').forEach(modal => {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) {
                    modal.classList.remove('show');
                }
            });
        });
        
        // Entry points management
        document.getElementById('add-entry-point').addEventListener('click', () => this.addEntryPoint());
        this.setupEntryPointListeners();
    }

    async compile() {
        if (!this.isWasmLoaded || !this.wasmModule) {
            this.updateStatus('WASM module not loaded');
            this.showAssembly('; Error: WASM module not loaded');
            return;
        }
        if (this.language === 'cedar') {
            await this.compileCedar();
        } else if (this.language === 'azure') {
            await this.compileAzurePolicyDefinition();
        } else {
            await this.compileRego();
        }
    }

    async compileRego() {
        const policy = this.editors.policy.getValue().trim();
        if (!policy) {
            this.showAssembly('');
            this.currentProgram = null;
            return;
        }

        try {
            this.updateStatus('Compiling Rego policy...');
            const startTime = performance.now();

            const data = this.editors.data.getValue().trim() || '{}';
            const entryPoints = this.getEntryPoints();
            const modules = [{ id: 'policy.rego', content: policy }];

            this.currentProgram = this.wasmModule.Program.compileFromModules(
                data,
                JSON.stringify(modules),
                JSON.stringify(entryPoints)
            );

            const format = document.getElementById('assembly-format').value || 'readable';
            const assembly = format === 'tabular'
                ? this.currentProgram.generateTabularListing()
                : this.currentProgram.generateListing();

            const endTime = performance.now();
            const compilationTime = (endTime - startTime).toFixed(2);

            this.showAssembly(assembly);
            if (typeof this.currentProgram.getInstructionCount === 'function') {
                this.updateInstructionCount(this.currentProgram.getInstructionCount());
            } else {
                this.updateInstructionCount(this.countInstructions(assembly));
            }
            this.updateStatus(`Compiled successfully (${compilationTime}ms)`);
        } catch (error) {
            console.error('Compilation error:', error);
            const errorMessage = error.message || error.toString() || 'Unknown compilation error';
            this.updateStatus(`Compilation failed: ${errorMessage}`);
            this.showAssembly(`; Compilation Error:\n; ${errorMessage}`);
            this.currentProgram = null;
        }
    }

    async compileCedar() {
        const policy = this.editors.policy.getValue().trim();
        if (!policy) {
            this.showAssembly('');
            this.currentProgram = null;
            return;
        }

        try {
            this.updateStatus('Compiling Cedar policy...');
            const startTime = performance.now();

            const specs = [{ id: 'policy.cedar', content: policy }];
            this.currentProgram = this.wasmModule.Program.compileCedarPolicies(
                JSON.stringify(specs)
            );

            const format = document.getElementById('assembly-format').value || 'readable';
            const assembly = format === 'tabular'
                ? this.currentProgram.generateTabularListing()
                : this.currentProgram.generateListing();

            const endTime = performance.now();
            const compilationTime = (endTime - startTime).toFixed(2);

            this.showAssembly(assembly);
            if (typeof this.currentProgram.getInstructionCount === 'function') {
                this.updateInstructionCount(this.currentProgram.getInstructionCount());
            } else {
                this.updateInstructionCount(this.countInstructions(assembly));
            }
            this.updateStatus(`Compiled successfully (${compilationTime}ms)`);
        } catch (error) {
            console.error('Compilation error:', error);
            const errorMessage = error.message || error.toString() || 'Unknown compilation error';
            this.updateStatus(`Compilation failed: ${errorMessage}`);
            this.showAssembly(`; Compilation Error:\n; ${errorMessage}`);
            this.currentProgram = null;
        }
    }

    async compileAzurePolicyDefinition() {
        const policy = this.editors.policy.getValue().trim();
        if (!policy) {
            this.showAssembly('');
            this.currentProgram = null;
            return;
        }

        if (!this.wasmModule?.Program?.compileAzurePolicyDefinition) {
            this.updateStatus('Azure Policy support missing - rebuild WASM');
            this.showAssembly('; Error: Azure Policy support missing in WASM');
            this.currentProgram = null;
            return;
        }

        try {
            this.updateStatus('Compiling Azure Policy definition...');
            const startTime = performance.now();

            const aliasMapJson = this.getAzureAliasMapJson();
            this.currentProgram = this.wasmModule.Program.compileAzurePolicyDefinition(
                policy,
                aliasMapJson
            );

            const format = document.getElementById('assembly-format').value || 'readable';
            const assembly = format === 'tabular'
                ? this.currentProgram.generateTabularListing()
                : this.currentProgram.generateListing();

            const endTime = performance.now();
            const compilationTime = (endTime - startTime).toFixed(2);

            this.showAssembly(assembly);
            if (typeof this.currentProgram.getInstructionCount === 'function') {
                this.updateInstructionCount(this.currentProgram.getInstructionCount());
            } else {
                this.updateInstructionCount(this.countInstructions(assembly));
            }
            this.updateStatus(`Compiled successfully (${compilationTime}ms)`);
        } catch (error) {
            console.error('Compilation error:', error);
            const errorMessage = error.message || error.toString() || 'Unknown compilation error';
            this.updateStatus(`Compilation failed: ${errorMessage}`);
            this.showAssembly(`; Compilation Error:\n; ${errorMessage}`);
            this.currentProgram = null;
        }
    }

    extractEntryPoint(policy) {
        // Simple heuristic to find entry point
        const lines = policy.split('\n');
        for (const line of lines) {
            const trimmed = line.trim();
            if (trimmed.startsWith('allow') && !trimmed.includes('{')) {
                return 'data.' + this.extractPackageName(policy) + '.allow';
            }
            if (trimmed.match(/^[a-zA-Z_][a-zA-Z0-9_]*\s*[:=]/)) {
                const ruleName = trimmed.split(/[:=]/)[0].trim();
                return 'data.' + this.extractPackageName(policy) + '.' + ruleName;
            }
        }
        return 'data.' + this.extractPackageName(policy) + '.allow'; // fallback
    }

    extractPackageName(policy) {
        const packageMatch = policy.match(/package\s+([a-zA-Z_][a-zA-Z0-9_.]*)/);
        return packageMatch ? packageMatch[1] : 'main';
    }

    generateMockAssembly(policy) {
        // This is a mock function - in reality, this would use the WASM module
        const lines = policy.split('\n').filter(line => line.trim());
        let assembly = '; RVM Assembly - Mock Generated\n';
        assembly += '; Instructions: ~' + (lines.length * 3) + ', Literals: ~' + (lines.length) + '\n';
        assembly += ';\n';
        assembly += '; LITERALS (JSON values):\n';
        assembly += ';   L 0: "package"\n';
        assembly += ';   L 1: "allow"\n';
        assembly += ';   L 2: true\n';
        assembly += ';\n';
        assembly += '; ===== RULE: data.authz.allow =====\n';
        assembly += '000: RuleInit     data.authz.allow → r0 {\n';
        assembly += '001:     LoadInput    r1 ← input                   ; Load global input document\n';
        assembly += '002:     IndexLiteral r2 ← r1[L0]                 ; Index with literal key: r1["user"]\n';
        assembly += '003:     IndexLiteral r3 ← r2[L1]                 ; Index with literal key: r2["role"]\n';
        assembly += '004:     Load         r4 ← L2                    ; Load literal: "admin"\n';
        assembly += '005:     Eq           r5 ← (r3 = r4)             ; Equality test: r3 == r4\n';
        assembly += '006:     AssertCondition assert r5                ; Assert r5 is true (exit if false/undefined)\n';
        assembly += '007:     LoadTrue     r0 ← true                  ; Load boolean constant true\n';
        assembly += '008: } return from rule                           ; End of rule evaluation\n';
        
        return assembly;
    }

    countInstructions(assembly) {
        const lines = assembly.split('\n');
        let count = 0;
        for (const line of lines) {
            if (/^\d{3}:/.test(line.trim())) {
                count++;
            }
        }
        return count;
    }

    showAssembly(assembly) {
        const display = document.getElementById('assembly-display');
        this.assemblyText = assembly;
        this.renderAssembly(display, assembly);
    }

    clearAssembly() {
        this.showAssembly('');
        this.updateInstructionCount(0);
    }

    renderAssembly(element, assembly) {
        this.assemblyLineMap.clear();
        this.activeAssemblyLine = null;

        const lines = assembly.split('\n');
        const rendered = lines.map(line => {
            const escaped = this.escapeHtml(line);
            const formatted = escaped
                .replace(/(\b\w+:)/g, '<span class="assembly-instruction">$1</span>')
                .replace(/(r\d+)/g, '<span class="assembly-register">$1</span>')
                .replace(/(L\d+)/g, '<span class="assembly-literal">$1</span>')
                .replace(/(;.*$)/gm, '<span class="assembly-comment">$1</span>')
                .replace(/(^\d{3}:)/gm, '<span class="assembly-address">$1</span>')
                .replace(/(===== RULE: .* =====)/g, '<span class="assembly-rule">$1</span>');

            const match = line.match(/^\s*(\d+):/);
            if (match) {
                const pc = Number.parseInt(match[1], 10);
                return `<span class="assembly-line" data-pc="${pc}">${formatted}</span>`;
            }
            return `<span class="assembly-line">${formatted}</span>`;
        });

        element.innerHTML = rendered.join('');
        element.querySelectorAll('.assembly-line[data-pc]').forEach(node => {
            const pc = Number.parseInt(node.dataset.pc, 10);
            if (!Number.isNaN(pc)) {
                this.assemblyLineMap.set(pc, node);
            }
        });
    }

    escapeHtml(value) {
        return value
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    async evaluate() {
        if (this.language === 'cedar') {
            await this.evaluateCedar();
        } else if (this.language === 'azure') {
            await this.evaluateAzurePolicy();
        } else {
            await this.evaluateRego();
        }
    }

    async evaluateRego() {
        const policy = this.editors.policy.getValue().trim();
        const input = this.editors.input.getValue().trim() || '{}';
        const data = this.editors.data.getValue().trim() || '{}';

        if (!policy) {
            this.showResults('No policy to evaluate', 'error');
            return;
        }

        if (!this.currentProgram) {
            await this.compile();
            if (!this.currentProgram) {
                this.showResults('Compilation failed - cannot evaluate', 'error');
                return;
            }
        }

        try {
            this.updateStatus('Evaluating Rego policy...');
            const startTime = performance.now();

            const vm = new this.wasmModule.Rvm();
            vm.loadProgram(this.currentProgram);
            vm.setInputJson(input);
            vm.setDataJson(data);

            const entryPoints = this.getEntryPoints();
            const results = {};
            entryPoints.forEach(entryPoint => {
                const resultJson = vm.executeEntryPoint(entryPoint);
                results[entryPoint] = JSON.parse(resultJson);
            });

            const endTime = performance.now();
            const evaluationTime = (endTime - startTime).toFixed(2);
            const formattedResult = this.formatEvaluationResult(results, input, data, policy, evaluationTime);
            this.showResults(formattedResult, 'success');

            this.updateStatus(`Evaluation completed (${evaluationTime}ms)`);
        } catch (error) {
            console.error('Evaluation error:', error);
            this.updateStatus(`Evaluation failed: ${error.message}`);
            this.showResults(`Error: ${error.message}`, 'error');
        }
    }

    async debugStep() {
        if (!this.isWasmLoaded || !this.wasmModule) {
            this.updateStatus('WASM module not loaded');
            return;
        }

        if (!this.currentProgram) {
            await this.compile();
            if (!this.currentProgram) {
                this.updateStatus('Compilation failed - cannot debug');
                return;
            }
        }

        if (!this.ensureDebugApiAvailable()) {
            return;
        }

        if (!this.debugSession.active || !this.debugSession.vm) {
            const started = this.startDebugSession();
            if (!started) {
                return;
            }
        }

        try {
            const vm = this.debugSession.vm;
            let resultJson;

            if (!this.debugSession.started) {
                this.debugSession.started = true;
                if (this.debugSession.entryPoint) {
                    resultJson = vm.executeEntryPoint(this.debugSession.entryPoint);
                } else {
                    resultJson = vm.execute();
                }
            } else {
                resultJson = vm.resume(null);
            }

            const state = this.getExecutionState(vm);
            if (!state) {
                this.updateStatus('Debug state unavailable - rebuild WASM');
                this.resetDebugSession(false);
                return;
            }
            if (state && state.pc !== null && state.pc !== undefined) {
                this.highlightAssemblyPc(state.pc);
                await this.highlightPolicyForPc(state.pc);
            }

            if (state?.state === 'Completed') {
                this.updateStatus('Debug complete');
                this.resetDebugSession(false);
                this.showResults(this.formatDebugResult(resultJson), 'success');
            } else if (state?.state === 'Error') {
                this.updateStatus(`Debug error: ${state.reason || 'unknown error'}`);
                this.resetDebugSession(false);
                this.showResults(`Error: ${state.reason || 'unknown error'}`, 'error');
            } else {
                this.updateStatus(`Debug step (${state?.reason || 'running'})`);
            }
        } catch (error) {
            console.error('Debug step error:', error);
            this.updateStatus(`Debug failed: ${error.message}`);
            this.resetDebugSession(false);
        }
    }

    ensureDebugApiAvailable() {
        if (!this.wasmModule?.Rvm || !this.wasmModule?.Program) {
            this.updateStatus('WASM module not loaded');
            return false;
        }

        const vm = new this.wasmModule.Rvm();
        const missing = [];
        if (typeof vm.setStepMode !== 'function') {
            missing.push('setStepMode');
        }
        if (typeof vm.getExecutionStateJson !== 'function') {
            missing.push('getExecutionStateJson');
        }
        if (this.currentProgram && typeof this.currentProgram.getInstructionSpanJson !== 'function') {
            missing.push('getInstructionSpanJson');
        }

        if (missing.length > 0) {
            this.updateStatus(`Debug API missing: ${missing.join(', ')} - rebuild WASM`);
            return false;
        }

        return true;
    }

    startDebugSession() {
        const vm = new this.wasmModule.Rvm();
        if (typeof vm.setStepMode !== 'function' || typeof vm.getExecutionStateJson !== 'function') {
            this.updateStatus('Debug API missing - rebuild WASM');
            return false;
        }

        vm.loadProgram(this.currentProgram);
        vm.setExecutionMode(1);
        vm.setStepMode(true);

        if (this.language === 'cedar') {
            const requestJson = this.editors.input.getValue().trim() || '{}';
            const entitiesJson = this.editors.data.getValue().trim() || '{}';
            const inputPayload = this.buildCedarInput(requestJson, entitiesJson);
            vm.setInputJson(JSON.stringify(inputPayload));
            this.debugSession.entryPoint = 'cedar.authorize';
        } else if (this.language === 'azure') {
            const inputJson = this.editors.input.getValue().trim() || '{}';
            const inputPayload = this.buildAzureInputEnvelope(inputJson);
            vm.setInputJson(JSON.stringify(inputPayload));
            this.debugSession.entryPoint = null;
        } else {
            const input = this.editors.input.getValue().trim() || '{}';
            const data = this.editors.data.getValue().trim() || '{}';
            vm.setInputJson(input);
            vm.setDataJson(data);
            const entryPoints = this.getEntryPoints();
            this.debugSession.entryPoint = entryPoints.length > 0 ? entryPoints[0] : null;
        }

        this.debugSession.active = true;
        this.debugSession.started = false;
        this.debugSession.vm = vm;
        this.debugSession.language = this.language;
        this.updateStatus('Debug session ready');
        return true;
    }

    resetDebugSession(clearStatus = true) {
        this.debugSession.active = false;
        this.debugSession.started = false;
        this.debugSession.vm = null;
        this.debugSession.entryPoint = null;
        this.debugSession.language = null;
        this.clearDebugHighlights();
        if (clearStatus) {
            this.updateStatus('Debug reset');
        }
    }

    clearDebugHighlights() {
        if (this.activeAssemblyLine) {
            this.activeAssemblyLine.classList.remove('active');
            this.activeAssemblyLine = null;
        }
        if (this.editors.policy && this.policyDecorations.length > 0) {
            this.policyDecorations = this.editors.policy.deltaDecorations(this.policyDecorations, []);
        }
    }

    getExecutionState(vm) {
        if (typeof vm.getExecutionStateJson !== 'function') {
            return null;
        }
        try {
            return JSON.parse(vm.getExecutionStateJson());
        } catch (error) {
            console.warn('Failed to parse execution state:', error);
            return null;
        }
    }

    highlightAssemblyPc(pc) {
        if (this.activeAssemblyLine) {
            this.activeAssemblyLine.classList.remove('active');
        }
        const line = this.assemblyLineMap.get(pc);
        if (line) {
            line.classList.add('active');
            line.scrollIntoView({ block: 'center', behavior: 'smooth' });
            this.activeAssemblyLine = line;
        }
    }

    async highlightPolicyForPc(pc) {
        if (!this.currentProgram || !this.editors.policy) {
            return;
        }
        if (typeof this.currentProgram.getInstructionSpanJson !== 'function') {
            return;
        }
        const spanJson = this.currentProgram.getInstructionSpanJson(pc);
        if (!spanJson || spanJson === 'null') {
            return;
        }
        let span;
        try {
            span = JSON.parse(spanJson);
        } catch (error) {
            console.warn('Invalid span json:', error);
            return;
        }

        if (!span || !span.line || !span.column) {
            return;
        }

        const lineNumber = Math.max(1, span.line);
        const startColumn = Math.max(1, span.column);
        const endColumn = Math.max(startColumn + 1, startColumn + (span.length || 1));

        const range = new monaco.Range(lineNumber, startColumn, lineNumber, endColumn);
        this.policyDecorations = this.editors.policy.deltaDecorations(this.policyDecorations, [
            { range, options: { inlineClassName: 'policy-highlight' } }
        ]);
        this.editors.policy.revealLineInCenter(lineNumber);
    }

    formatDebugResult(resultJson) {
        try {
            const value = JSON.parse(resultJson);
            return `# Debug Result\n\n\`\`\`json\n${JSON.stringify(value, null, 2)}\n\`\`\``;
        } catch (error) {
            return `# Debug Result\n\n${resultJson}`;
        }
    }

    async evaluateCedar() {
        const policy = this.editors.policy.getValue().trim();
        const requestJson = this.editors.input.getValue().trim() || '{}';
        const entitiesJson = this.editors.data.getValue().trim() || '{}';

        if (!policy) {
            this.showResults('No policy to evaluate', 'error');
            return;
        }

        if (!this.currentProgram) {
            await this.compile();
            if (!this.currentProgram) {
                this.showResults('Compilation failed - cannot evaluate', 'error');
                return;
            }
        }

        try {
            this.updateStatus('Evaluating Cedar policy...');
            const startTime = performance.now();

            const inputPayload = this.buildCedarInput(requestJson, entitiesJson);
            const vm = new this.wasmModule.Rvm();
            vm.loadProgram(this.currentProgram);
            vm.setInputJson(JSON.stringify(inputPayload));

            const resultJson = vm.executeEntryPoint('cedar.authorize');
            const resultValue = JSON.parse(resultJson);
            const decision = this.formatCedarDecision(resultValue);

            const endTime = performance.now();
            const evaluationTime = (endTime - startTime).toFixed(2);
            const formattedResult = this.formatCedarEvaluationResult(
                decision,
                inputPayload,
                evaluationTime
            );
            this.showResults(formattedResult, 'success');

            this.updateStatus(`Evaluation completed (${evaluationTime}ms)`);
        } catch (error) {
            console.error('Evaluation error:', error);
            this.updateStatus(`Evaluation failed: ${error.message}`);
            this.showResults(`Error: ${error.message}`, 'error');
        }
    }

    async evaluateAzurePolicy() {
        const policy = this.editors.policy.getValue().trim();
        const inputJson = this.editors.input.getValue().trim() || '{}';

        if (!policy) {
            this.showResults('No policy to evaluate', 'error');
            return;
        }

        if (!this.wasmModule?.Program?.compileAzurePolicyDefinition) {
            this.showResults('Azure Policy support missing - rebuild WASM', 'error');
            return;
        }

        if (!this.currentProgram) {
            await this.compile();
            if (!this.currentProgram) {
                this.showResults('Compilation failed - cannot evaluate', 'error');
                return;
            }
        }

        try {
            this.updateStatus('Evaluating Azure Policy...');
            const startTime = performance.now();

            const inputPayload = this.buildAzureInputEnvelope(inputJson);
            const vm = new this.wasmModule.Rvm();
            vm.loadProgram(this.currentProgram);
            vm.setInputJson(JSON.stringify(inputPayload));

            const resultJson = vm.execute();
            const resultValue = JSON.parse(resultJson);

            const endTime = performance.now();
            const evaluationTime = (endTime - startTime).toFixed(2);
            const formattedResult = this.formatAzureEvaluationResult(
                resultValue,
                inputPayload,
                evaluationTime
            );
            this.showResults(formattedResult, 'success');
            this.updateStatus(`Evaluation completed (${evaluationTime}ms)`);
        } catch (error) {
            console.error('Evaluation error:', error);
            this.updateStatus(`Evaluation failed: ${error.message}`);
            this.showResults(`Error: ${error.message}`, 'error');
        }
    }

    formatEvaluationResult(result, input, data, policy, evaluationTime = null) {
        let output = '# Evaluation Results\n\n';
        
        // Extract main result vs debug/trace information
        let mainResult = result;
        let debugInfo = null;
        let printStatements = null;
        
        // If result is an object with debug info, separate it
        if (typeof result === 'object' && result !== null) {
            if (result.result !== undefined) {
                mainResult = result.result;
                debugInfo = { ...result };
                delete debugInfo.result;
            } else if (result.value !== undefined) {
                mainResult = result.value;
                debugInfo = { ...result };
                delete debugInfo.value;
            }
            
            // Extract print statements if present
            if (result.prints) {
                printStatements = result.prints;
                if (debugInfo) delete debugInfo.prints;
            }
        }
        
        // Display main policy result in highlighted JSON box
        output += `## Policy Result\n`;
        output += '<div class="json-result-box">\n';
        output += '<pre><code class="language-json">';
        output += JSON.stringify(mainResult, null, 2);
        output += '</code></pre>\n';
        output += '</div>\n\n';
        
        // Show print statements and logs in separate section
        if (printStatements && printStatements.length > 0) {
            output += `## Execution Logs\n`;
            output += '<div class="logs-container">\n';
            printStatements.forEach(print => {
                // Handle newlines properly in print statements
                const cleanPrint = print.replace(/\\n/g, '\n').replace(/\\t/g, '\t');
                output += `<div class="log-entry">${cleanPrint}</div>\n`;
            });
            output += '</div>\n\n';
        }
        
        // Show debug/trace information if present
        if (debugInfo && Object.keys(debugInfo).length > 0) {
            output += `## Debug Information\n`;
            output += '```json\n';
            output += JSON.stringify(debugInfo, null, 2);
            output += '\n```\n\n';
        }
        
        // Show program information if available
        if (this.currentProgram && typeof this.currentProgram.getProgramInfo === 'function') {
            output += `## Program Information\n`;
            output += '```\n';
            const programInfo = this.currentProgram.getProgramInfo();
            // Handle newlines in program info
            const cleanProgramInfo = programInfo.replace(/\\n/g, '\n');
            output += cleanProgramInfo;
            output += '```\n\n';
        }
        
        return output;
    }

    formatCedarDecision(value) {
        if (value === 1) {
            return 'ALLOW';
        }
        if (value === 0) {
            return 'DENY';
        }
        return `UNKNOWN (${value})`;
    }

    buildCedarInput(requestJson, entitiesJson) {
        const request = this.safeParseJson(requestJson, 'request');
        const entities = this.safeParseJson(entitiesJson, 'entities');

        if (typeof request !== 'object' || request === null || Array.isArray(request)) {
            throw new Error('Cedar request must be a JSON object');
        }
        if (typeof entities !== 'object' || entities === null || Array.isArray(entities)) {
            throw new Error('Cedar entities must be a JSON object');
        }

        if (!request.entities) {
            return { ...request, entities };
        }

        return request;
    }

    formatCedarEvaluationResult(decision, inputPayload, evaluationTime = null) {
        let output = '# Cedar Authorization\n\n';
        output += `## Decision\n`;
        output += '<div class="json-result-box">\n';
        output += `<pre><code>${decision}</code></pre>\n`;
        output += '</div>\n\n';

        return output;
    }

    formatAzureEvaluationResult(resultValue, inputPayload, evaluationTime = null) {
        const effect = this.extractAzureEffect(resultValue);
        const badge = effect
            ? `<span class="result-badge effect-${effect.toLowerCase()}">${effect.toUpperCase()}</span>`
            : '<span class="result-badge">UNKNOWN</span>';

        let output = '# Azure Policy Evaluation\n\n';
        output += '## Effect\n';
        output += `<div class="json-result-box">${badge}</div>\n\n`;
        output += '## Result\n';
        output += '```json\n';
        output += JSON.stringify(resultValue, null, 2);
        output += '\n```\n\n';

        return output;
    }

    extractAzureEffect(resultValue) {
        if (typeof resultValue === 'string') {
            return resultValue;
        }
        if (resultValue && typeof resultValue.effect === 'string') {
            return resultValue.effect;
        }
        if (resultValue && typeof resultValue.value === 'string') {
            return resultValue.value;
        }
        return null;
    }

    safeParseJson(value, label) {
        try {
            return JSON.parse(value || '{}');
        } catch (error) {
            throw new Error(`Invalid ${label} JSON: ${error.message}`);
        }
    }

    buildAzureAliasMap(catalog) {
        const map = {};
        if (!Array.isArray(catalog)) {
            return map;
        }
        catalog.forEach(provider => {
            const namespace = provider.namespace;
            const resourceTypes = provider.resourceTypes || [];
            resourceTypes.forEach(resourceType => {
                const fqType = `${namespace}/${resourceType.resourceType}`;
                const prefix = `${fqType}/`;
                (resourceType.aliases || []).forEach(alias => {
                    const name = alias.name || '';
                    if (name.length > prefix.length && name.toLowerCase().startsWith(prefix.toLowerCase())) {
                        const shortName = name.slice(prefix.length);
                        map[name.toLowerCase()] = shortName;
                    }
                });
            });
        });
        return map;
    }

    buildAzureAliasIndex(catalog) {
        const index = {};
        if (!Array.isArray(catalog)) {
            return index;
        }
        catalog.forEach(provider => {
            const namespace = provider.namespace;
            const resourceTypes = provider.resourceTypes || [];
            resourceTypes.forEach(resourceType => {
                const fqType = `${namespace}/${resourceType.resourceType}`;
                index[fqType.toLowerCase()] = resourceType.aliases || [];
            });
        });
        return index;
    }

    getAzureAliasMapJson() {
        const entries = Object.keys(this.azureAliases.aliasMap || {});
        if (entries.length === 0) {
            return undefined;
        }
        return JSON.stringify(this.azureAliases.aliasMap);
    }

    buildAzureInputEnvelope(inputJson) {
        const input = this.safeParseJson(inputJson, 'input');
        if (typeof input !== 'object' || input === null || Array.isArray(input)) {
            throw new Error('Azure Policy input must be a JSON object');
        }

        const resource = input.resource || input;
        const context = input.context || {};
        const parameters = input.parameters || {};

        if (typeof resource !== 'object' || resource === null || Array.isArray(resource)) {
            throw new Error('Azure Policy resource must be a JSON object');
        }

        return {
            resource: this.normalizeAzureResource(resource),
            context,
            parameters
        };
    }

    normalizeAzureResource(resource) {
        const rootFields = [
            'name',
            'type',
            'location',
            'kind',
            'id',
            'tags',
            'identity',
            'sku',
            'plan',
            'zones',
            'managedBy',
            'etag',
            'apiVersion',
            'fullName'
        ];

        const normalized = {};
        rootFields.forEach(field => {
            if (Object.prototype.hasOwnProperty.call(resource, field)) {
                normalized[field] = resource[field];
            }
        });

        if (resource.properties && typeof resource.properties === 'object') {
            Object.entries(resource.properties).forEach(([key, value]) => {
                if (!Object.prototype.hasOwnProperty.call(normalized, key)) {
                    normalized[key] = value;
                }
            });
        }

        const aliases = this.getAzureAliasesForType(resource.type);
        if (aliases) {
            this.applyAzureAliasEntries(normalized, resource, aliases, resource.type);
        }

        return normalized;
    }

    getAzureAliasesForType(resourceType) {
        if (!resourceType || !this.azureAliases.aliasesByType) {
            return null;
        }
        return this.azureAliases.aliasesByType[String(resourceType).toLowerCase()] || null;
    }

    applyAzureAliasEntries(target, resource, aliases, resourceType) {
        const prefix = resourceType ? `${resourceType}/` : '';
        aliases.forEach(alias => {
            const name = alias.name || '';
            const defaultPath = alias.defaultPath || alias.default_path;
            if (!defaultPath) {
                return;
            }
            if (defaultPath.includes('[*]')) {
                return;
            }
            let shortName = name;
            if (prefix && name.length > prefix.length && name.toLowerCase().startsWith(prefix.toLowerCase())) {
                shortName = name.slice(prefix.length);
            }
            if (shortName.includes('[*]')) {
                return;
            }
            const value = this.readAzurePath(resource, defaultPath);
            if (value === undefined) {
                return;
            }
            this.setNestedValue(target, shortName, value);
        });
    }

    readAzurePath(resource, path) {
        if (!path || typeof path !== 'string') {
            return undefined;
        }
        if (path.includes('[*]')) {
            return undefined;
        }
        const segments = path.split('.');
        let current = resource;
        for (const segment of segments) {
            if (!current || typeof current !== 'object') {
                return undefined;
            }
            current = current[segment];
        }
        return current;
    }

    setNestedValue(target, path, value) {
        const segments = path.split('.');
        if (segments.length === 0) {
            return;
        }
        let current = target;
        segments.slice(0, -1).forEach(segment => {
            if (!current[segment] || typeof current[segment] !== 'object') {
                current[segment] = {};
            }
            current = current[segment];
        });
        current[segments[segments.length - 1]] = value;
    }

    generateMockEvaluation(policy, input, data) {
        // Mock evaluation result
        const inputObj = JSON.parse(input);
        
        let result = '# Evaluation Results\n\n';
        
        if (policy.includes('allow')) {
            const userRole = inputObj.user?.role || 'unknown';
            const allowed = userRole === 'admin' || (inputObj.user?.id === inputObj.resource?.owner);
            
            result += `## Policy Decision\n`;
            result += `**allow**: ${allowed}\n\n`;
            
            result += `## Trace\n`;
            result += `1. Loaded input: user.role = "${userRole}"\n`;
            result += `2. Evaluated rule: data.authz.allow\n`;
            result += `3. Result: ${allowed}\n\n`;
        }
        
        return result;
    }

    showResults(content, type = 'success') {
        const display = document.getElementById('results-display');
        
        // For markdown content, render as HTML with basic formatting
        if (content.includes('# ') || content.includes('## ') || content.includes('```')) {
            // Simple markdown-to-HTML conversion
            let htmlContent = content
                .replace(/^# (.+)$/gm, '<h1>$1</h1>')
                .replace(/^## (.+)$/gm, '<h2>$1</h2>')
                .replace(/^### (.+)$/gm, '<h3>$1</h3>')
                .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
                .replace(/`([^`]+)`/g, '<code>$1</code>')
                .replace(/```(\w+)?\n([\s\S]*?)```/g, '<pre><code class="language-$1">$2</code></pre>')
                .replace(/```\n([\s\S]*?)```/g, '<pre><code>$1</code></pre>')
                .replace(/\n/g, '<br>')
                .replace(/<\/h[1-6]><br>/g, function(match) {
                    return match.replace('<br>', '');
                });
            
            // Handle collapsible details/summary elements
            htmlContent = htmlContent.replace(
                /<details><summary>(.+?)<\/summary><br><br>/g, 
                '<details><summary>$1</summary><div class="details-content">'
            );
            htmlContent = htmlContent.replace(/<\/details>/g, '</div></details>');
            
            display.innerHTML = htmlContent;
        } else {
            display.textContent = content;
        }
        
        display.className = `results-output ${type}`;
        
        // Switch to results tab
        this.switchTab('results');
    }

    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.tab-button').forEach(btn => {
            btn.classList.toggle('active', btn.dataset.tab === tabName);
        });
        
        // Update tab panes
        document.querySelectorAll('.tab-pane').forEach(pane => {
            pane.classList.toggle('active', pane.id === `${tabName}-tab`);
        });
    }

    showSettings() {
        const modal = document.getElementById('settings-modal');
        
        // Update settings form with current values
        document.getElementById('setting-word-wrap').checked = this.settings.wordWrap;
        document.getElementById('setting-minimap').checked = this.settings.minimap;
        document.getElementById('setting-theme').value = this.settings.theme;
        document.getElementById('setting-show-addresses').checked = this.settings.showAddresses;
        document.getElementById('setting-show-comments').checked = this.settings.showComments;
        document.getElementById('setting-auto-evaluate').checked = this.settings.autoEvaluate;
        
        // Add event listeners for settings
        this.setupSettingsListeners();
        
        modal.classList.add('show');
    }

    setupSettingsListeners() {
        const applySettings = () => {
            this.settings.wordWrap = document.getElementById('setting-word-wrap').checked;
            this.settings.minimap = document.getElementById('setting-minimap').checked;
            this.settings.theme = document.getElementById('setting-theme').value;
            this.settings.showAddresses = document.getElementById('setting-show-addresses').checked;
            this.settings.showComments = document.getElementById('setting-show-comments').checked;
            this.settings.autoEvaluate = document.getElementById('setting-auto-evaluate').checked;
            
            this.applyEditorSettings();
            this.saveSettings();
        };
        
        document.querySelectorAll('#settings-modal input, #settings-modal select').forEach(input => {
            input.removeEventListener('change', applySettings); // Prevent duplicate listeners
            input.addEventListener('change', applySettings);
        });
    }

    applyEditorSettings() {
        Object.values(this.editors).forEach(editor => {
            const isPolicyEditor = editor === this.editors.policy;
            editor.updateOptions({
                theme: this.settings.theme,
                wordWrap: this.settings.wordWrap ? 'on' : 'off',
                minimap: { enabled: isPolicyEditor ? false : this.settings.minimap }
            });
        });
    }

    showExamples(type) {
        const modal = document.getElementById('examples-modal');
        const title = document.getElementById('examples-modal-title');
        const list = document.getElementById('examples-list');
        const tabs = document.getElementById('examples-tabs');
        
        title.textContent = `Example ${type === 'policies' ? 'Policies' : 'Data'}`;
        
        list.innerHTML = '';
        tabs.innerHTML = '';
        
        if (type === 'policies') {
            const renderComparative = () => {
                if (this.comparativeExamples.length === 0) {
                    list.innerHTML = '<p class="empty-state">No comparative examples available.</p>';
                    return;
                }

                this.comparativeExamples.forEach(example => {
                    const item = document.createElement('div');
                    item.className = 'example-item';
                    const variantButtons = Object.keys(example.variants || {}).map(language => {
                        const label = language.toUpperCase();
                        return `<button class="example-action" data-role="compare-load" data-lang="${language}">Load ${label}</button>`;
                    }).join('');
                    item.innerHTML = `
                        <h4>${example.name}</h4>
                        <p>${example.description}</p>
                        <div class="example-actions">
                            ${variantButtons}
                        </div>
                    `;
                    item.querySelectorAll('.example-action[data-role="compare-load"]').forEach(button => {
                        button.addEventListener('click', (event) => {
                            event.stopPropagation();
                            const language = button.dataset.lang;
                            this.loadComparativeExample(example, language);
                            modal.classList.remove('show');
                        });
                    });
                    list.appendChild(item);
                });
            };

            const renderLanguageExamples = (language) => {
                let examplesByCategory = this.examples.categories;
                if (language === 'cedar') {
                    examplesByCategory = this.cedarExamples.categories;
                } else if (language === 'azure') {
                    examplesByCategory = this.azureExamples.categories;
                }

                Object.entries(examplesByCategory).forEach(([categoryName, examples]) => {
                    const categoryHeader = document.createElement('div');
                    categoryHeader.className = 'example-category-header';
                    categoryHeader.innerHTML = `<h3>${categoryName}</h3>`;
                    list.appendChild(categoryHeader);

                    examples.forEach(example => {
                        const item = document.createElement('div');
                        item.className = 'example-item';
                        item.innerHTML = `
                            <h4>${example.name}</h4>
                            <p>${example.description}</p>
                            <div class="example-meta">
                                <span class="category-tag">${categoryName}</span>
                                <span class="category-tag">${language.toUpperCase()}</span>
                            </div>
                        `;
                        item.addEventListener('click', () => {
                            this.loadExample({ ...example, language });
                            modal.classList.remove('show');
                        });
                        list.appendChild(item);
                    });
                });
            };

            const renderTab = (tab) => {
                list.innerHTML = '';
                if (tab === 'comparative') {
                    renderComparative();
                } else if (tab === 'rego') {
                    renderLanguageExamples('rego');
                } else if (tab === 'azure') {
                    renderLanguageExamples('azure');
                } else {
                    renderLanguageExamples('cedar');
                }
            };

            const tabsConfig = [
                { id: 'comparative', label: 'Comparative' },
                { id: 'rego', label: 'Rego' },
                { id: 'cedar', label: 'Cedar' },
                { id: 'azure', label: 'Azure Policy' }
            ];

            const activeTab = localStorage.getItem('rvmPlaygroundExamplesTab') || 'comparative';
            tabsConfig.forEach(tab => {
                const button = document.createElement('button');
                button.className = 'examples-tab';
                button.textContent = tab.label;
                button.dataset.tab = tab.id;
                button.addEventListener('click', () => {
                    localStorage.setItem('rvmPlaygroundExamplesTab', tab.id);
                    tabs.querySelectorAll('.examples-tab').forEach(btn => {
                        btn.classList.toggle('active', btn.dataset.tab === tab.id);
                    });
                    renderTab(tab.id);
                });
                tabs.appendChild(button);
            });

            tabs.querySelectorAll('.examples-tab').forEach(btn => {
                btn.classList.toggle('active', btn.dataset.tab === activeTab);
            });
            renderTab(activeTab);
        }
        
        modal.classList.add('show');
    }

    loadExample(example) {
        const exampleLanguage = example.language || this.language;
        if (this.language !== exampleLanguage) {
            this.setLanguage(exampleLanguage);
        }
        if (example.isComparative) {
            this.lastComparativeExampleName = example.comparativeName || example.name;
            localStorage.setItem('rvmPlaygroundLastComparative', this.lastComparativeExampleName);
        } else {
            this.lastComparativeExampleName = null;
            localStorage.removeItem('rvmPlaygroundLastComparative');
        }
        this.applyExample(example, exampleLanguage, `Loaded example: ${example.name}`);
    }

    applyExample(example, exampleLanguage, statusMessage) {
        this.editors.policy.setValue(example.policy);
        this.editors.input.setValue(example.input || '{}');
        if (exampleLanguage === 'cedar') {
            this.editors.data.setValue(example.entities || '{}');
        } else if (exampleLanguage === 'azure') {
            this.editors.data.setValue('{}');
        } else {
            this.editors.data.setValue(example.data || '{}');
        }

        if (example.entryPoints && exampleLanguage === 'rego') {
            this.languageState.rego.entryPoints = [...example.entryPoints];
            this.updateEntryPointsUI();
            this.saveEntryPoints();
        }

        this.setPolicyTitle(example.name || 'Policy');
        this.storeCurrentLanguageState();
        this.saveLastExampleState(example, exampleLanguage);
        if (statusMessage) {
            this.updateStatus(statusMessage);
        }
    }

    loadComparativeExample(example, language) {
        const variant = example.variants[language];
        if (!variant) {
            return;
        }
        this.loadExample({
            ...variant,
            name: example.name,
            isComparative: true,
            comparativeName: example.name
        });
        this.updateStatus(`Loaded comparative example: ${example.name}`);
    }

    clearPolicy() {
        if (confirm('Clear the current policy?')) {
            this.editors.policy.setValue('');
            this.showAssembly('');
            this.updateStatus('Policy cleared');
        }
    }

    refreshAssembly() {
        if (this.currentProgram) {
            const format = document.getElementById('assembly-format').value || 'readable';
            const assembly = format === 'tabular'
                ? this.currentProgram.generateTabularListing()
                : this.currentProgram.generateListing();
            this.showAssembly(assembly);
        }
    }

    copyAssembly() {
        const assembly = document.getElementById('assembly-display').textContent;
        if (assembly) {
            navigator.clipboard.writeText(assembly).then(() => {
                this.updateStatus('Assembly copied to clipboard');
            }).catch(err => {
                console.error('Failed to copy:', err);
            });
        }
    }

    // Utility methods
    debounce(func, wait) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(func, wait);
    }

    updateStatus(message) {
        document.getElementById('status-text').textContent = message;
    }

    updateVMStatus(message) {
        document.getElementById('vm-status').textContent = `VM: ${message}`;
    }


    updateInstructionCount(count) {
        document.getElementById('instruction-count').textContent = `Instructions: ${count}`;
    }

    saveSettings() {
        localStorage.setItem('rvmPlaygroundSettings', JSON.stringify(this.settings));
    }

    loadSettings() {
        const saved = localStorage.getItem('rvmPlaygroundSettings');
        if (saved) {
            this.settings = { ...this.settings, ...JSON.parse(saved) };
            this.applyEditorSettings();
        }
        
        const savedEntryPoints = localStorage.getItem('rvmPlaygroundEntryPoints');
        if (savedEntryPoints) {
            this.languageState.rego.entryPoints = JSON.parse(savedEntryPoints);
            if (this.language === 'rego') {
                this.updateEntryPointsUI();
            }
        }
    }

    loadLanguagePreference() {
        const savedLanguage = localStorage.getItem('rvmPlaygroundLanguage');
        if (savedLanguage && savedLanguage !== this.language) {
            this.setLanguage(savedLanguage);
            return;
        }
        this.updateLanguageUI();
        const languageSelect = document.getElementById('language-select');
        if (languageSelect) {
            languageSelect.value = this.language;
        }
    }

    saveLanguagePreference() {
        localStorage.setItem('rvmPlaygroundLanguage', this.language);
    }

    storeCurrentLanguageState() {
        if (!this.editors.policy) {
            return;
        }
        const policyTitle = this.getPolicyTitle();
        if (this.language === 'cedar') {
            this.languageState.cedar.policy = this.editors.policy.getValue();
            this.languageState.cedar.input = this.editors.input.getValue();
            this.languageState.cedar.entities = this.editors.data.getValue();
            this.languageState.cedar.policyTitle = policyTitle;
        } else if (this.language === 'azure') {
            this.languageState.azure.policy = this.editors.policy.getValue();
            this.languageState.azure.input = this.editors.input.getValue();
            this.languageState.azure.policyTitle = policyTitle;
        } else {
            this.languageState.rego.policy = this.editors.policy.getValue();
            this.languageState.rego.input = this.editors.input.getValue();
            this.languageState.rego.data = this.editors.data.getValue();
            this.languageState.rego.policyTitle = policyTitle;
        }
    }

    getPolicyEditorLanguageId() {
        if (this.language === 'cedar') {
            return 'cedar';
        }
        if (this.language === 'azure') {
            return 'json';
        }
        return 'rego';
    }

    setLanguage(language) {
        if (language !== 'rego' && language !== 'cedar' && language !== 'azure') {
            return;
        }
        if (this.language === language) {
            return;
        }
        const previousLanguage = this.language;
        this.storeCurrentLanguageState();
        this.language = language;
        this.updateLanguageUI();
        this.saveLanguagePreference();

        const languageSelect = document.getElementById('language-select');
        if (languageSelect) {
            languageSelect.value = this.language;
        }

        const policyModel = this.editors.policy?.getModel();
        if (policyModel && typeof monaco !== 'undefined') {
            monaco.editor.setModelLanguage(policyModel, this.getPolicyEditorLanguageId());
        }

        const state = this.languageState[this.language];
        if (this.lastComparativeExampleName) {
            const example = this.comparativeExamples.find(item => item.name === this.lastComparativeExampleName);
            if (example && example.variants[this.language]) {
                this.loadComparativeExample(example, this.language);
                return;
            }
        }
        if (state.policy) {
            this.editors.policy?.setValue(state.policy || '');
            this.editors.input?.setValue(state.input || '{}');
            if (this.language === 'cedar') {
                this.editors.data?.setValue(state.entities || '{}');
            } else if (this.language === 'azure') {
                this.editors.data?.setValue('{}');
            } else {
                this.editors.data?.setValue(state.data || '{}');
                this.updateEntryPointsUI();
            }
            const lastExample = this.getLastExampleState(this.language);
            this.setPolicyTitle(state.policyTitle || lastExample?.policyTitle || `${this.language.toUpperCase()} policy`);
        } else {
            const lastExample = this.getLastExampleState(this.language);
            if (lastExample) {
                this.applyExample(lastExample, this.language, `Loaded last example: ${lastExample.name || this.language.toUpperCase()}`);
            } else {
                this.loadDefaultExampleForLanguage();
            }
        }

        this.currentProgram = null;
        this.clearAssembly();
        this.updateStatus(`Switched to ${this.language.toUpperCase()} mode`);
    }

    updateLanguageUI() {
        document.body.classList.toggle('cedar-mode', this.language === 'cedar');
        document.body.classList.toggle('azure-mode', this.language === 'azure');

        const dataTab = document.querySelector('.tab-button[data-tab="data"]');
        if (dataTab) {
            if (this.language === 'cedar') {
                dataTab.textContent = 'Entities';
            } else {
                dataTab.textContent = 'Data';
            }
        }

        const dataHeader = document.getElementById('data-panel-title');
        if (dataHeader) {
            if (this.language === 'cedar') {
                dataHeader.textContent = 'Input & Entities';
            } else if (this.language === 'azure') {
                dataHeader.textContent = 'Input & Results';
            } else {
                dataHeader.textContent = 'Data & Results';
            }
        }

        if (this.language === 'azure') {
            const activeTab = document.querySelector('.tab-button.active');
            if (activeTab && activeTab.dataset.tab === 'data') {
                this.switchTab('input');
            }
        }

    }

    getExamplesForLanguage() {
        if (this.language === 'cedar') {
            return this.cedarExamples.categories;
        }
        if (this.language === 'azure') {
            return this.azureExamples.categories;
        }
        return this.examples.categories;
    }

    setPolicyTitle(title) {
        const element = document.getElementById('policy-title');
        if (element) {
            element.textContent = this.normalizePolicyTitle(title);
        }
    }

    getPolicyTitle() {
        const element = document.getElementById('policy-title');
        return element ? element.textContent : '';
    }

    normalizePolicyTitle(title) {
        if (!title) {
            return '';
        }
        let normalized = title.replace(/\s*\(Rego\s+vs\s+Cedar\)\s*/i, '');
        normalized = normalized.replace(/\s*\((REGO|CEDAR)\)\s*$/i, '');
        return normalized.trim();
    }

    loadDefaultExampleForLanguage() {
        const examples = this.getExamplesForLanguage();
        const firstCategory = Object.keys(examples)[0];
        const firstExample = examples[firstCategory][0];
        this.applyExample(firstExample, this.language, `Loaded example: ${firstExample.name}`);
    }

    loadInitialExampleForLanguage() {
        const lastExample = this.getLastExampleState(this.language);
        if (lastExample) {
            this.applyExample(lastExample, this.language, `Loaded last example: ${lastExample.name || this.language.toUpperCase()}`);
            return;
        }
        this.loadDefaultExampleForLanguage();
    }

    getLastExampleState(language) {
        const raw = localStorage.getItem(`rvmPlaygroundLastExample:${language}`);
        if (!raw) {
            return null;
        }
        try {
            return JSON.parse(raw);
        } catch (error) {
            console.warn('Failed to parse last example state:', error);
            return null;
        }
    }

    saveLastExampleState(example, language) {
        const payload = {
            name: this.normalizePolicyTitle(example.name),
            policy: example.policy,
            input: example.input || '{}',
            data: example.data || '{}',
            entities: example.entities || '{}',
            entryPoints: example.entryPoints || [],
            policyTitle: this.normalizePolicyTitle(example.name) || 'Policy'
        };
        localStorage.setItem(`rvmPlaygroundLastExample:${language}`, JSON.stringify(payload));
    }
    
    setupEntryPointListeners() {
        const container = document.getElementById('entry-points-list');
        container.addEventListener('click', (e) => {
            if (e.target.classList.contains('entry-point-remove')) {
                this.removeEntryPoint(e.target);
            }
        });
        
        container.addEventListener('input', (e) => {
            if (e.target.classList.contains('entry-point-input')) {
                this.updateEntryPointsFromUI();
            }
        });
    }
    
    addEntryPoint() {
        const container = document.getElementById('entry-points-list');
        const newItem = document.createElement('div');
        newItem.className = 'entry-point-item';
        newItem.innerHTML = `
            <input type="text" class="entry-point-input" value="" placeholder="e.g., data.package.rule">
            <button class="entry-point-remove" title="Remove entry point">×</button>
        `;
        container.appendChild(newItem);
        newItem.querySelector('input').focus();
        this.updateEntryPointsFromUI();
    }
    
    removeEntryPoint(button) {
        const item = button.parentElement;
        const container = document.getElementById('entry-points-list');
        if (container.children.length > 1) {
            item.remove();
            this.updateEntryPointsFromUI();
        }
    }
    
    updateEntryPointsFromUI() {
        if (this.language !== 'rego') {
            return;
        }
        const inputs = document.querySelectorAll('.entry-point-input');
        this.languageState.rego.entryPoints = Array.from(inputs)
            .map(input => input.value.trim())
            .filter(value => value.length > 0);
        
        this.saveEntryPoints();
    }
    
    saveEntryPoints() {
        localStorage.setItem('rvmPlaygroundEntryPoints', JSON.stringify(this.languageState.rego.entryPoints));
    }
    
    updateEntryPointsUI() {
        const container = document.getElementById('entry-points-list');
        container.innerHTML = '';

        this.languageState.rego.entryPoints.forEach(entryPoint => {
            const item = document.createElement('div');
            item.className = 'entry-point-item';
            item.innerHTML = `
                <input type="text" class="entry-point-input" value="${entryPoint}" placeholder="e.g., data.package.rule">
                <button class="entry-point-remove" title="Remove entry point">×</button>
            `;
            container.appendChild(item);
        });

        if (this.languageState.rego.entryPoints.length === 0) {
            this.addEntryPoint();
        }
    }
    
    getEntryPoints() {
        this.updateEntryPointsFromUI();
        return this.languageState.rego.entryPoints.length > 0
            ? this.languageState.rego.entryPoints
            : ['data.main.allow'];
    }
}

// Initialize the playground when the DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.playground = new RVMPlayground();
});