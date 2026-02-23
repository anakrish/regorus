# Complex Azure Policy Test Candidates from Regolator

Analysis of ~4,860 real Azure Policy JSON definitions in
`regolator/policyDefinitions/`. Listed below are complex policies that exercise
untested or under-tested compiler features. Each entry includes the source file,
display name, effect type, and the specific compiler features it would exercise.

---

## Already Covered (13 e2e tests)

| YAML Test File | Policy | Key Features |
|----------------|--------|-------------|
| `e2e_vm_skus_allowed` | Compute/VMSkusAllowed_Deny | `not` + `in` parameter |
| `e2e_double_encryption` | Compute/DoubleEncryptionRequired_Deny | type + notEquals |
| `e2e_vm_managed_disk` | Compute/VMRequireManagedDisk_Audit | anyOf + allOf, `exists`, multi-type |
| `e2e_storage_vnet_rules` | Storage/StorageAccountOnlyVnetRulesEnabled_Audit | `count.field` + alias resolution |
| `e2e_aks_zone_redundant` | Resilience/ContainerService_managedclusters_ZoneRedundant | Nested count (agentPoolProfiles → availabilityZones) |
| `e2e_nsg_rdp_access` | Network/NetworkSecurityGroup_RDPAccess_Audit | `and()`, `not()`, `lessOrEquals()`, `greaterOrEquals()`, `if()`, port ranges |
| `e2e_nsg_ssh_access` | Network/NetworkSecurityGroup_SSHAccess_Audit | Same as RDP but for SSH (port 22) |
| `e2e_keyvault_firewall` | Key Vault/FirewallEnabled_Audit | `ipRangeContains()`, named value count |
| `e2e_sql_server_auditing` | SQL/SqlServerAuditing_Audit | AuditIfNotExists, `existenceCondition` |
| `e2e_servicebus_diagnostic_logs` | Service Bus/AuditDiagnosticLog_Audit | AuditIfNotExists, `padLeft()` |
| `e2e_activitylog_capture_all_regions` | Monitoring/ActivityLog_CaptureAllRegions | AuditIfNotExists (subscription-scope) |
| `e2e_storage_ip_allowlist` | Storage/StorageAccountIpAllowList_Audit | count + where + template functions |
| `e2e_storage_ip_allowlist_custom` | (custom variant) | ipRangeContains with CIDR |

---

## Priority 1 — Unique Untested Patterns

### 1. Value Count with `name`/`current()` — VirtualEnclaves Approved Subnets

- **File:** `VirtualEnclaves/ApprovedVirtualNetworkSubnets_Deny.json`
- **Display Name:** "Network interfaces should be connected to an approved subnet of the approved virtual network"
- **Effect:** Deny (parameterized)
- **Resource Type:** `Microsoft.Network/networkInterfaces`
- **Features Exercised:**
  - **Value count** — `count.value` over `parameters('allowedSubnetList')` with `name: "subnetName"` and `current('subnetName')`.
    This is the only policy found using named value count. Completely untested.
  - `not` + `like` with `concat` on wildcard alias `ipconfigurations[*].subnet.id`
  - Conditional branch: `parameters('allowAllSubnets')` == true vs false via nested allOf
- **Why:** Exercises the named value count iteration pattern, which is a distinct code path from field count.

### 2. Nested Count-in-Count — Azure Firewall Routing (AINE)

- **File:** `Network/ASC_All_Internet_traffic_should_be_routed_via_Azure_Firewall.json`
- **Display Name:** "All Internet traffic should be routed via your deployed Azure Firewall"
- **Effect:** AuditIfNotExists (parameterized)
- **Resource Type:** `Microsoft.Network/virtualNetworks` → `Microsoft.Network/azureFirewalls`
- **Features Exercised:**
  - **Nested count** — inner count on `subnets[*].ipConfigurations[*]` inside outer count's `where`
  - AuditIfNotExists with **count in existenceCondition**
  - Complex ARM expression: `concat(subscription().subscriptionId, ..., first(split(field('fullName'), '/')), ...)`
  - `empty()` function, `not` + `anyOf` inside where clause
- **Why:** Most complex single policy — combines nested count, AINE existenceCondition with count, `subscription()`, `first()`, `split()`, `field('fullName')`.

### 3. Four Modify Operations — Storage Network Bypass

- **File:** `VirtualEnclaves/StorageNetworkAccessBypassOnly_Modify.json`
- **Display Name:** "Configure Storage Accounts to restrict network access through network ACL bypass configuration only"
- **Effect:** Modify (parameterized)
- **Resource Type:** `Microsoft.Storage/storageAccounts`
- **Features Exercised:**
  - **4 Modify operations** (most of any policy): sets `defaultAction`, clears `ipRules` to `[]`, clears `virtualNetworkRules` to `[]`, sets `bypass` to parameter
  - 3 bare count expressions (no `where`): `ipRules[*]`, `resourceAccessRules[*]`, `virtualNetworkRules[*]`
  - `conflictEffect: audit`
- **Why:** Tests multi-operation Modify compilation, including array-clearing operations. Also tests bare count (count without where).

### 4. Append Effect — Container Instance Log Analytics

- **File:** `Container Instances/ContainerInstance_LogAnalytics_Append.json`
- **Display Name:** "Configure diagnostics for container group to log analytics workspace"
- **Effect:** Append (parameterized)
- **Resource Type:** `Microsoft.ContainerInstance/containerGroups`
- **Features Exercised:**
  - **Append effect** with array details (2 field/value pairs)
  - `exists: false` checks in if-condition
  - Parameterized values from `parameters('workspaceId')` and `parameters('workspaceKey')`
- **Why:** Append is an untested effect type. This is the cleanest example.

### 5. Triple Double-Negation in existenceCondition — SQL Auditing Action-Groups

- **File:** `SQL/SqlServerAuditing_ActionsAndGroups_Audit.json`
- **Display Name:** "SQL Auditing settings should have Action-Groups configured to capture critical activities"
- **Effect:** AuditIfNotExists (parameterized)
- **Resource Type:** `Microsoft.Sql/servers` → `Microsoft.Sql/servers/auditingSettings`
- **Features Exercised:**
  - **Triple** `not` + `notEquals` on `[*]` wildcard in existenceCondition's `allOf`
  - AINE with named child resource (`name: "default"`)
  - Cross-resource check: checks that `auditActionsAndGroups[*]` contains 3 specific values
- **Why:** Classic "contains all of these values" pattern via triple double-negation. Tests AINE existenceCondition with wildcard aliases.

### 6. Complex ARM Functions in Count/Where — Cosmos DB Locations

- **File:** `Cosmos DB/Cosmos_Locations_Deny.json`
- **Display Name:** "Azure Cosmos DB allowed locations"
- **Effect:** Deny (parameterized)
- **Resource Type:** `Microsoft.DocumentDB/databaseAccounts`
- **Features Exercised:**
  - `replace(toLower(first(field('...Locations[*].locationName'))), ' ', '')` — deeply nested ARM functions
  - Count comparison with dynamic value: `notEquals: [length(field('...Locations[*]'))]`
  - `first()` function, `replace()` function
- **Why:** Tests the most complex ARM function nesting seen in any count/where clause.

### 7. `resourceGroup()` Dynamic Property Access — Tags Inherit Modify

- **File:** `Tags/InheritTag_AddOrReplace_Modify.json`
- **Display Name:** "Inherit a tag from the resource group"
- **Effect:** Modify (hardcoded)
- **Resource Type:** Any (mode: Indexed)
- **Features Exercised:**
  - **`resourceGroup().tags[parameters('tagName')]`** — dynamic property access on `resourceGroup()` result
  - `concat('tags[', parameters('tagName'), ']')` — dynamic field name via `concat`
  - Modify with `addOrReplace` operation using `resourceGroup()` as value source
- **Why:** Tests `resourceGroup()` function integration and dynamic property access using bracket notation with parameters.

---

## Priority 2 — Diverse Effect Types and Patterns

### 8. Modify with `requestContext().apiVersion` Condition — Cosmos DB

- **File:** `Cosmos DB/Cosmos_PrivateNetworkAccess_Modify.json`
- **Display Name:** "Configure CosmosDB accounts to disable public network access"
- **Effect:** Modify (parameterized)
- **Resource Type:** `Microsoft.DocumentDB/databaseAccounts`
- **Features Exercised:**
  - Modify operation with `condition: [greaterOrEquals(requestContext().apiVersion, '2021-01-15')]`
  - `conflictEffect`, multiple `roleDefinitionIds`
- **Why:** Tests `requestContext().apiVersion` in operation conditions — an untested feature.

### 9. Three Count Expressions — Cosmos DB Firewall Rules

- **File:** `Cosmos DB/Cosmos_NetworkRulesExist_Audit.json`
- **Display Name:** "Azure Cosmos DB accounts should have firewall rules"
- **Effect:** Deny (parameterized)
- **Resource Type:** `Microsoft.DocumentDB/databaseAccounts`
- **Features Exercised:**
  - 3 count expressions in one policy (ipRules, privateEndpointConnections with where)
  - `exists: false` alternatives
  - Deep allOf/anyOf/allOf nesting (4 levels)
  - Bare count (`count.field` without where) and count with where
- **Why:** Tests multiple count expressions in a single policy evaluation path.

### 10. Simplest Double-Negation — NIC Public IP Deny

- **File:** `Network/NetworkPublicIPNic_Deny.json`
- **Display Name:** "Network interfaces should not have public IPs"
- **Effect:** Deny (hardcoded)
- **Resource Type:** `Microsoft.Network/networkInterfaces`
- **Features Exercised:**
  - `not { field[*] notLike "*" }` — simplest possible double negation
  - Wildcard `[*]` alias: `ipconfigurations[*].publicIpAddress.id`
- **Why:** Minimal test for the double-negation pattern. Very clean — good baseline test.

### 11. Doubly-Nested Wildcard with `requestContext()` — Portal Dashboard

- **File:** `Portal/SharedDashboardInlineContent_Deny.json`
- **Display Name:** "Shared dashboards should not have markdown tiles with inline content"
- **Effect:** Deny (parameterized)
- **Resource Type:** `Microsoft.Portal/dashboards`
- **Features Exercised:**
  - **Doubly-nested wildcard** in count: `lenses[*].parts[*]`
  - `requestContext().apiVersion` check with `not` + `greaterOrEquals`
  - Very long alias paths with Extension metadata names
  - Count + where + allOf with nested `anyOf`
- **Why:** Tests double-level wildcard in count field and extremely long alias paths.

### 12. Four Double-Negation Operator Types — Custom Owner Role

- **File:** `General/CustomSubscription_OwnerRole_Audit.json`
- **Display Name:** "Custom subscription owner roles should not exist"
- **Effect:** Audit (parameterized)
- **Resource Type:** `Microsoft.Authorization/roleDefinitions`
- **Features Exercised:**
  - 4 different double-negation combinations in one policy: `not`+`notEquals`, `not`+`notIn`, `not`+`notLike`
  - Doubly-nested wildcard: `permissions[*].actions[*]`
  - `concat(subscription().id, '/')` and `subscription().id`
- **Why:** Tests all double-negation operator combinations in a single policy. Also exercises `subscription()` function.

### 13. Count+Where with allOf in Where — App Service TLS

- **File:** `App Service/HostingEnvironment_DisableTls_Audit.json`
- **Display Name:** "App Service Environment should have TLS 1.0 and 1.1 disabled"
- **Effect:** Audit (parameterized)
- **Resource Type:** `Microsoft.Web/hostingEnvironments`
- **Features Exercised:**
  - Count + where with `allOf` checking **two fields simultaneously** (name AND value)
  - `kind` field with `like "ASE*"` pattern
  - `less` count comparison (inverted logic)
- **Why:** Clean mid-complexity count test. Two field checks inside `where.allOf` is a common real-world pattern.

### 14. Append with Dynamic Field Name — Tags Append

- **File:** `Tags/ApplyTag_Append.json`
- **Display Name:** "Append a tag and its value to resources"
- **Effect:** Append (hardcoded)
- **Resource Type:** Any (mode: Indexed)
- **Features Exercised:**
  - Append effect with single detail
  - `concat('tags[', parameters('tagName'), ']')` — dynamic field name
  - `exists: false` check on dynamic field
- **Why:** Tests Append with dynamic field name. Simpler than Container Instance but uses template expressions in field references.

### 15. Simple VNet DDoS Modify Baseline

- **File:** `Network/VirtualNetworkDdosStandard_Audit.json`
- **Display Name:** "Virtual networks should be protected by Azure DDoS Protection"
- **Effect:** Modify (parameterized)
- **Resource Type:** `Microsoft.Network/virtualNetworks`
- **Features Exercised:**
  - 2 Modify operations (addOrReplace): one setting boolean, one setting parameter reference
  - `conflictEffect` configuration
- **Why:** Simplest clean Modify with 2 operations. Good baseline Modify test.

### 16. Simple AINE Baseline — PostgreSQL PgAudit

- **File:** `PostgreSQL/FlexibleServers_EnablePgAudit_AINE.json`
- **Display Name:** "Auditing with PgAudit should be enabled for PostgreSQL flexible servers"
- **Effect:** AuditIfNotExists (parameterized)
- **Resource Type:** `Microsoft.DBforPostgreSQL/flexibleServers` → `.../configurations`
- **Features Exercised:**
  - Simple AINE with named child resource (`name: "pgaudit.log"`)
  - existenceCondition using `notEquals`
- **Why:** Simplest possible AINE with named child resource. Good baseline for existenceCondition.

---

## Priority 3 — Additional Coverage

### 17. `requestContext()` in Both if and Operation Condition — Storage Public Blob

- **File:** `Storage/StorageAccountDisablePublicBlobAccess_Modify.json`
- **Display Name:** "Configure your Storage account public access to be disallowed"
- **Effect:** Modify (parameterized)
- **Resource Type:** `Microsoft.Storage/storageAccounts`
- **Features Exercised:**
  - `requestContext().apiVersion` in if-condition (with `less`)
  - `requestContext().apiVersion` in operation condition (with `greaterOrEquals`)
  - Nested allOf/anyOf with `exists`
- **Why:** Tests `requestContext()` used in both the if-condition and the operation condition with different comparison operators.

### 18. `not` + Wildcard + `concat` — Approved Virtual Network

- **File:** `Network/ApprovedVirtualNetwork_Audit.json`
- **Display Name:** "Virtual machines should be connected to an approved virtual network"
- **Effect:** Audit (parameterized)
- **Resource Type:** `Microsoft.Network/networkInterfaces`
- **Features Exercised:**
  - `not { field[*] like concat(parameter, '/*') }` — double-negation-like pattern
  - `ipconfigurations[*].subnet.id` wildcard alias
- **Why:** Tests `not` with `like` and `concat` on wildcard alias. Compact but exercises key patterns.

### 19. Stream Analytics Data Exfiltration

- **File:** `Stream Analytics/DataExfiltration_Audit.json`
- **Display Name:** (Stream Analytics data exfiltration prevention)
- **Effect:** Audit/Deny (parameterized)
- **Resource Type:** `Microsoft.StreamAnalytics/streamingjobs`
- **Features Exercised:**
  - Large policy (~340 lines) with deep nesting
  - Multiple field checks on streaming job configurations
- **Why:** Large policy with diverse operator usage.

### 20. DeployIfNotExists with Tag-Based Filtering — VM Replication

- **File:** `Compute/VirtualMachineReplication_AzureSiteRecovery_DINE.json`
- **Display Name:** "Configure disaster recovery on virtual machines by enabling replication via Azure Site Recovery"
- **Effect:** DeployIfNotExists (parameterized)
- **Resource Type:** `Microsoft.Compute/virtualMachines` → `Microsoft.Resources/links`
- **Features Exercised:**
  - DINE with existenceCondition (`like` + `contains`)
  - Tag-based inclusion/exclusion with `concat('tags[', parameters('tagName'), ']')`
  - Cross-resource type check to `Microsoft.Resources/links`
  - 12 parameters — very parameter-heavy
- **Why:** Complex DINE with tag filtering and existenceCondition.

---

## Summary — Feature Coverage Matrix

| Feature | Already Tested | New Candidates |
|---------|---------------|----------------|
| Value count (`name`/`current()`) | No | #1 |
| Nested count-in-count | Partially (#aks) | #2 |
| Modify (multi-operation) | No | #3, #15 |
| Append effect | No | #4, #14 |
| Double-negation in existenceCondition | No | #5 |
| `replace()`/`first()` in count/where | No | #6 |
| `resourceGroup()` dynamic access | No | #7 |
| `requestContext().apiVersion` | No | #8, #11, #17 |
| Multiple counts in one policy | No | #9 |
| Simple double-negation baseline | No | #10 |
| Doubly-nested wildcard `[*].[*]` | No | #11, #12 |
| All double-negation operator types | No | #12 |
| Count+where with multi-field allOf | No | #13 |
| `subscription()` function | No | #2, #12 |
| AINE with named child resource | Partially (#sql) | #5, #16 |
| Tag-based DINE filtering | No | #20 |
| Conditional Modify operations | No | #8, #17 |

---

## Recommended Implementation Order

**Phase 1** — New effect types and fundamental patterns (4 tests):
1. `e2e_nic_public_ip_deny` — #10 (simplest double-negation baseline)
2. `e2e_container_diagnostics_append` — #4 (Append effect)
3. `e2e_vnet_ddos_modify` — #15 (simple Modify baseline)
4. `e2e_tags_inherit_modify` — #7 (`resourceGroup()` + dynamic field + Modify)

**Phase 2** — Count patterns (4 tests):
5. `e2e_appservice_tls_count` — #13 (count+where with allOf)
6. `e2e_cosmos_firewall_multicount` — #9 (3 counts in one policy)
7. `e2e_cosmos_locations_deny` — #6 (complex ARM functions in count)
8. `e2e_approved_subnets_valuecount` — #1 (value count with `name`/`current()`)

**Phase 3** — Advanced patterns (4 tests):
9. `e2e_sql_audit_actions_aine` — #5 (triple double-negation in existenceCondition)
10. `e2e_custom_owner_role` — #12 (4 double-negation types + `subscription()`)
11. `e2e_portal_dashboard_deny` — #11 (doubly-nested wildcard + `requestContext()`)
12. `e2e_firewall_routing_aine` — #2 (nested count + AINE count + `subscription()`)

**Phase 4** — Modify/DINE edge cases (4 tests):
13. `e2e_storage_bypass_modify` — #3 (4 Modify operations)
14. `e2e_cosmos_modify_requestcontext` — #8 (conditional operation)
15. `e2e_storage_public_blob_modify` — #17 (`requestContext()` dual-use)
16. `e2e_vm_replication_dine` — #20 (complex DINE with tags)
