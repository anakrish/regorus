# Alias Normalization — Naming Strategy and Implementation

This document specifies how Azure Policy aliases map to normalized field names,
how the normalizer transforms raw ARM JSON into the `input.resource` structure,
and how the compiler consumes the result. For the design rationale and
alternative approaches considered, see [Alias Design Discussion](aliases.md).

---

## 1. Alias Anatomy

A fully-qualified Azure Policy alias has this structure:

```
<Namespace>/<ResourceType>[/<SubType>...]/<PropertyPath>
```

Example breakdown:

```
Microsoft.Network/networkSecurityGroups/securityRules[*].protocol
├───────────────┘ └──────────────────┘ └──────────────────────────┘
    Namespace         ResourceType            PropertyPath
```

| Component | Description | Examples |
|:----------|:-----------|:---------|
| **Namespace** | ARM resource provider | `Microsoft.Network`, `Microsoft.Storage`, `Microsoft.Compute` |
| **ResourceType** | One or more `/`-delimited type segments | `networkSecurityGroups`, `virtualMachines/extensions` |
| **PropertyPath** | `.`-delimited path with optional `[*]` | `securityRules[*].protocol`, `networkAcls.defaultAction`, `sku.name` |

The **resource type prefix** is `<Namespace>/<ResourceType>/`. Everything after
it is the **property path**, which we also call the **alias short name**.

---

## 2. The Core Rule

> **The alias short name IS the normalized field path.**

Given a resource of type `T` and an alias `T/P`, the short name `P` is the
exact path into `input.resource` where the resolved value lives.

No mapping table is consulted at evaluation time. No name translation occurs in
the compiler or VM. The normalizer produces a JSON structure that makes this
correspondence hold by construction.

---

## 3. Short Name Derivation

### 3.1 Provider aliases

Strip the resource type prefix:

| Full alias | Resource type | Short name |
|:-----------|:-------------|:-----------|
| `Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly` | `Microsoft.Storage/storageAccounts` | `supportsHttpsTrafficOnly` |
| `Microsoft.Storage/storageAccounts/networkAcls.ipRules[*].value` | `Microsoft.Storage/storageAccounts` | `networkAcls.ipRules[*].value` |
| `Microsoft.Network/networkSecurityGroups/securityRules[*].protocol` | `Microsoft.Network/networkSecurityGroups` | `securityRules[*].protocol` |
| `Microsoft.Compute/virtualMachines/storageProfile.osDisk.osType` | `Microsoft.Compute/virtualMachines` | `storageProfile.osDisk.osType` |
| `Microsoft.Compute/virtualMachines/extensions/type` | `Microsoft.Compute/virtualMachines/extensions` | `type` |
| `Microsoft.Storage/storageAccounts/sku.name` | `Microsoft.Storage/storageAccounts` | `sku.name` |
| `Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.storageProfile.osDisk.managedDisk.storageAccountType` | `Microsoft.Compute/virtualMachineScaleSets` | `virtualMachineProfile.storageProfile.osDisk.managedDisk.storageAccountType` |

Azure Policy JSON allows both the full qualified name and the short name in
`"field"` references. The compiler normalizes to the short name by stripping the
resource type prefix if present.

### 3.2 Built-in fields

A closed set of fields that exist on all ARM resources. These have no provider
prefix — they are already short names:

| Field | ARM location | Notes |
|:------|:-------------|:------|
| `name` | root | Resource name |
| `fullName` | root | Full name including parent (e.g., `parent/child`) |
| `type` | root | Resource type string |
| `location` | root | Azure region |
| `kind` | root | Resource kind (e.g., `StorageV2`) |
| `id` | root | Full ARM resource ID |
| `tags` | root | Tags object |
| `tags['key']` | root | Individual tag value |
| `identity.type` | root | Managed identity type |

### 3.3 Tag access

Tags use bracket notation in policies:

```json
{ "field": "tags['environment']", "equals": "production" }
{ "field": "tags['Acct.CostCenter']", "equals": "12345" }
```

Tag keys can contain dots, hyphens, spaces, and other characters that are not
valid Rego identifiers. In Rego, bracket notation handles this:

```rego
input.resource.tags.environment == "production"
input.resource.tags["Acct.CostCenter"] == "12345"
```

The compiler parses `tags['x']` as a chained index into
`["resource", "tags", "x"]`.

---

## 4. Short Name Grammar

```
ShortName   ::= Segment ( '.' Segment )*
Segment     ::= Identifier ArraySuffix?
ArraySuffix ::= '[*]'
Identifier  ::= [a-zA-Z_][a-zA-Z0-9_]*
```

Special cases handled outside this grammar:
- `tags['<key>']` — bracket notation for tag access
- `identity.type` — built-in field with dot separator

### 4.1 Short name to JSON path mapping

Each `.` in the short name represents one level of JSON object nesting. Each
`[*]` represents an array. The short name directly describes the shape of the
normalized JSON:

| Short name | Normalized JSON structure |
|:-----------|:------------------------|
| `supportsHttpsTrafficOnly` | `{ "supportsHttpsTrafficOnly": <value> }` |
| `networkAcls.defaultAction` | `{ "networkAcls": { "defaultAction": <value> } }` |
| `securityRules[*].protocol` | `{ "securityRules": [{ "protocol": <value> }, ...] }` |
| `networkAcls.ipRules[*].value` | `{ "networkAcls": { "ipRules": [{ "value": <value> }, ...] } }` |
| `sku.name` | `{ "sku": { "name": <value> } }` |
| `addressSpace.addressPrefixes[*]` | `{ "addressSpace": { "addressPrefixes": [<value>, ...] } }` |

### 4.2 Short name to Rego path mapping

Replace `.` with Rego field access. Replace `[*]` with iteration:

| Short name | Rego expression |
|:-----------|:---------------|
| `supportsHttpsTrafficOnly` | `input.resource.supportsHttpsTrafficOnly` |
| `networkAcls.defaultAction` | `input.resource.networkAcls.defaultAction` |
| `securityRules[*].protocol` | `some r in input.resource.securityRules; r.protocol` |
| `sku.name` | `input.resource.sku.name` |
| `tags['Acct.CostCenter']` | `input.resource.tags["Acct.CostCenter"]` |

### 4.3 Short name to RVM instructions

The compiler splits the short name on `.` and `[*]` to produce instruction
operands:

| Short name | RVM instructions |
|:-----------|:----------------|
| `supportsHttpsTrafficOnly` | `ChainedIndex { path: ["resource", "supportsHttpsTrafficOnly"] }` |
| `networkAcls.defaultAction` | `ChainedIndex { path: ["resource", "networkAcls", "defaultAction"] }` |
| `securityRules[*].protocol` | `ChainedIndex { path: ["resource", "securityRules"] }` → `LoopStart` → `ChainedIndex { path: ["protocol"] }` |
| `sku.name` | `ChainedIndex { path: ["resource", "sku", "name"] }` |

---

## 5. ARM JSON to Normalized JSON — The Normalizer

The normalizer transforms raw ARM resource JSON into the `input.resource`
structure. Its job: remove `properties` wrappers wherever aliases hide them, so
that alias short names become direct paths.

### 5.1 What the normalizer removes

ARM resources nest resource-specific fields under `properties`. Sub-resource
array elements may also have their own `properties` wrapper. Aliases hide all of
these.

| Alias short name | Raw ARM path | `properties` wrappers hidden |
|:----------------|:-------------|:-----------------------------|
| `supportsHttpsTrafficOnly` | `properties.supportsHttpsTrafficOnly` | 1 (root) |
| `securityRules[*].protocol` | `properties.securityRules[*].properties.protocol` | 2 (root + element) |
| `securityRules[*].name` | `properties.securityRules[*].name` | 1 (root only — `name` is on element envelope) |
| `sku.name` | `sku.name` | 0 (not under `properties`) |
| `storageProfile.osDisk.osType` | `properties.storageProfile.osDisk.osType` | 1 (root) |

### 5.2 Normalization rules

**Rule 1: Flatten root `properties`.**

Every ARM resource has a top-level `properties` object. Its contents are merged
into the normalized root alongside root-level fields.

```
ARM:          { "name": "x", "properties": { "a": 1, "b": 2 } }
Normalized:   { "name": "x", "a": 1, "b": 2 }
```

**Rule 2: Copy root-level fields as-is.**

Fields at the ARM root that are NOT `properties` are copied directly:
`name`, `type`, `location`, `kind`, `id`, `tags`, `identity`, `sku`, `plan`,
`zones`, `managedBy`, `etag`, `apiVersion`.

If a root-level field name collides with a `properties` field name, the
root-level field takes precedence (this doesn't happen in practice — ARM
schema design prevents it).

**Rule 3: Flatten sub-resource array elements.**

If an array element is a **sub-resource** (its elements have their own
`properties` wrapper), merge each element's `properties` into the element:

```
ARM element:    { "name": "r1", "properties": { "protocol": "Tcp" } }
Normalized:     { "name": "r1", "protocol": "Tcp" }
```

**Rule 4: Leave plain-object array elements alone.**

If an array element is a plain value object (no inner `properties`), copy it
as-is:

```
ARM element:    { "value": "10.0.0.1", "action": "Allow" }
Normalized:     { "value": "10.0.0.1", "action": "Allow" }
```

**Rule 5: Recurse for nested sub-resource arrays.**

Apply rules 3–4 recursively. If a sub-resource element itself contains arrays
of sub-resources, flatten those too.

**Rule 6: Primitive arrays pass through.**

Arrays of primitives (strings, numbers) are copied as-is:

```
ARM:          { "addressPrefixes": ["10.0.0.0/16", "172.16.0.0/12"] }
Normalized:   { "addressPrefixes": ["10.0.0.0/16", "172.16.0.0/12"] }
```

### 5.3 How to determine sub-resource vs. plain-object arrays

The normalizer needs to know which array fields contain sub-resource elements
(with `properties` to flatten) vs. plain objects or primitives. Three sources:

1. **From the alias table**: If any alias for the resource type has pattern
   `arr[*].prop` mapping to ARM path `properties.arr[*].properties.prop`, then
   `arr` is a sub-resource array.

2. **From the ARM resource schema**: If the array element schema has a
   `properties` property of type `object`, it's a sub-resource.

3. **From the resource data itself**: If an array element has a `properties`
   key, it's a sub-resource. This heuristic works in practice but is fragile —
   a field called `properties` that isn't a sub-resource wrapper would be
   incorrectly flattened.

Option 1 or 2 is preferred. Option 3 can serve as a fallback.

### 5.4 Normalization spec format

The normalizer's per-type configuration can be expressed compactly:

```json
{
  "Microsoft.Network/networkSecurityGroups": {
    "sub_resource_arrays": ["securityRules", "defaultSecurityRules"]
  },
  "Microsoft.Storage/storageAccounts": {
    "sub_resource_arrays": []
  },
  "Microsoft.Compute/virtualMachines": {
    "sub_resource_arrays": []
  }
}
```

- **`sub_resource_arrays`**: Array field names (at any nesting depth) whose
  elements have a `properties` wrapper to flatten. Root `properties` flattening
  is always applied (not listed).

For nested sub-resource arrays (arrays inside sub-resource elements that are
themselves sub-resources), the spec uses dotted paths:

```json
{
  "Microsoft.Network/virtualNetworks": {
    "sub_resource_arrays": [
      "subnets",
      "subnets.ipConfigurations"
    ]
  }
}
```

This spec is auto-derivable from the alias table by scanning for aliases with
the pattern `a[*].b` → `properties.a[*].properties.b`.

---

## 6. Concrete Normalization Examples

### 6.1 Network Security Group

**Raw ARM JSON:**
```json
{
  "id": "/subscriptions/.../networkSecurityGroups/myNsg",
  "name": "myNsg",
  "type": "Microsoft.Network/networkSecurityGroups",
  "location": "eastus",
  "tags": { "env": "prod" },
  "properties": {
    "securityRules": [
      {
        "name": "allowHttps",
        "type": "Microsoft.Network/networkSecurityGroups/securityRules",
        "properties": {
          "protocol": "Tcp",
          "access": "Allow",
          "direction": "Inbound",
          "sourceAddressPrefix": "*",
          "destinationPortRange": "443",
          "priority": 100
        }
      },
      {
        "name": "denyAll",
        "properties": {
          "protocol": "*",
          "access": "Deny",
          "direction": "Inbound",
          "sourceAddressPrefix": "*",
          "destinationPortRange": "*",
          "priority": 4096
        }
      }
    ],
    "defaultSecurityRules": [
      {
        "name": "AllowVnetInBound",
        "properties": {
          "protocol": "*",
          "access": "Allow",
          "direction": "Inbound"
        }
      }
    ]
  }
}
```

**Normalization spec:**
```json
{ "sub_resource_arrays": ["securityRules", "defaultSecurityRules"] }
```

**Normalized `input.resource`:**
```json
{
  "id": "/subscriptions/.../networkSecurityGroups/myNsg",
  "name": "myNsg",
  "type": "Microsoft.Network/networkSecurityGroups",
  "location": "eastus",
  "tags": { "env": "prod" },
  "securityRules": [
    {
      "name": "allowHttps",
      "protocol": "Tcp",
      "access": "Allow",
      "direction": "Inbound",
      "sourceAddressPrefix": "*",
      "destinationPortRange": "443",
      "priority": 100
    },
    {
      "name": "denyAll",
      "protocol": "*",
      "access": "Deny",
      "direction": "Inbound",
      "sourceAddressPrefix": "*",
      "destinationPortRange": "*",
      "priority": 4096
    }
  ],
  "defaultSecurityRules": [
    {
      "name": "AllowVnetInBound",
      "protocol": "*",
      "access": "Allow",
      "direction": "Inbound"
    }
  ]
}
```

**Alias verification:**

| Alias short name | Path into normalized | Value |
|:----------------|:--------------------|:------|
| `name` | `.name` | `"myNsg"` |
| `location` | `.location` | `"eastus"` |
| `tags['env']` | `.tags.env` | `"prod"` |
| `securityRules[*].protocol` | `.securityRules[0].protocol` | `"Tcp"` |
| `securityRules[*].access` | `.securityRules[1].access` | `"Deny"` |
| `securityRules[*].destinationPortRange` | `.securityRules[0].destinationPortRange` | `"443"` |
| `defaultSecurityRules[*].direction` | `.defaultSecurityRules[0].direction` | `"Inbound"` |

### 6.2 Storage Account

**Raw ARM JSON:**
```json
{
  "name": "mystorageacct",
  "type": "Microsoft.Storage/storageAccounts",
  "location": "westus2",
  "kind": "StorageV2",
  "sku": { "name": "Standard_LRS", "tier": "Standard" },
  "properties": {
    "supportsHttpsTrafficOnly": true,
    "isHnsEnabled": false,
    "networkAcls": {
      "defaultAction": "Deny",
      "ipRules": [
        { "value": "203.0.113.0/24", "action": "Allow" },
        { "value": "198.51.100.0/24", "action": "Allow" }
      ],
      "virtualNetworkRules": []
    },
    "encryption": {
      "services": {
        "blob": { "enabled": true },
        "file": { "enabled": true }
      },
      "keySource": "Microsoft.Storage"
    }
  }
}
```

**Normalization spec:**
```json
{ "sub_resource_arrays": [] }
```

Note: `ipRules` elements are plain objects (no inner `properties`), so they are
NOT sub-resource arrays.

**Normalized `input.resource`:**
```json
{
  "name": "mystorageacct",
  "type": "Microsoft.Storage/storageAccounts",
  "location": "westus2",
  "kind": "StorageV2",
  "sku": { "name": "Standard_LRS", "tier": "Standard" },
  "supportsHttpsTrafficOnly": true,
  "isHnsEnabled": false,
  "networkAcls": {
    "defaultAction": "Deny",
    "ipRules": [
      { "value": "203.0.113.0/24", "action": "Allow" },
      { "value": "198.51.100.0/24", "action": "Allow" }
    ],
    "virtualNetworkRules": []
  },
  "encryption": {
    "services": {
      "blob": { "enabled": true },
      "file": { "enabled": true }
    },
    "keySource": "Microsoft.Storage"
  }
}
```

**Alias verification:**

| Alias short name | Path into normalized | Value |
|:----------------|:--------------------|:------|
| `sku.name` | `.sku.name` | `"Standard_LRS"` |
| `kind` | `.kind` | `"StorageV2"` |
| `supportsHttpsTrafficOnly` | `.supportsHttpsTrafficOnly` | `true` |
| `networkAcls.defaultAction` | `.networkAcls.defaultAction` | `"Deny"` |
| `networkAcls.ipRules[*].value` | `.networkAcls.ipRules[0].value` | `"203.0.113.0/24"` |
| `networkAcls.ipRules` | `.networkAcls.ipRules` | `[{...}, {...}]` (entire array) |

### 6.3 Virtual Machine (deep nesting)

**Raw ARM JSON (abbreviated):**
```json
{
  "name": "myVm",
  "type": "Microsoft.Compute/virtualMachines",
  "location": "eastus",
  "properties": {
    "storageProfile": {
      "osDisk": {
        "osType": "Linux",
        "managedDisk": { "storageAccountType": "Premium_LRS" }
      },
      "imageReference": {
        "publisher": "Canonical",
        "offer": "UbuntuServer",
        "sku": "18.04-LTS"
      }
    },
    "osProfile": {
      "computerName": "myvm",
      "adminUsername": "azureuser"
    },
    "networkProfile": {
      "networkInterfaces": [
        { "id": "/subscriptions/.../nic1" },
        { "id": "/subscriptions/.../nic2" }
      ]
    }
  }
}
```

**Normalization spec:**
```json
{ "sub_resource_arrays": [] }
```

Note: `networkInterfaces` elements are reference objects (contain `id` but no
`properties`), not sub-resources.

**Normalized `input.resource`:**
```json
{
  "name": "myVm",
  "type": "Microsoft.Compute/virtualMachines",
  "location": "eastus",
  "storageProfile": {
    "osDisk": {
      "osType": "Linux",
      "managedDisk": { "storageAccountType": "Premium_LRS" }
    },
    "imageReference": {
      "publisher": "Canonical",
      "offer": "UbuntuServer",
      "sku": "18.04-LTS"
    }
  },
  "osProfile": {
    "computerName": "myvm",
    "adminUsername": "azureuser"
  },
  "networkProfile": {
    "networkInterfaces": [
      { "id": "/subscriptions/.../nic1" },
      { "id": "/subscriptions/.../nic2" }
    ]
  }
}
```

**Alias verification:**

| Alias short name | Path into normalized | Value |
|:----------------|:--------------------|:------|
| `storageProfile.osDisk.osType` | `.storageProfile.osDisk.osType` | `"Linux"` |
| `storageProfile.imageReference.publisher` | `.storageProfile.imageReference.publisher` | `"Canonical"` |
| `osProfile.computerName` | `.osProfile.computerName` | `"myvm"` |
| `networkProfile.networkInterfaces[*].id` | `.networkProfile.networkInterfaces[0].id` | `"/subscriptions/.../nic1"` |

---

## 7. Case Insensitivity

Azure Policy alias evaluation is **case-insensitive**. The alias
`Microsoft.Storage/storageAccounts/supportsHttpsTrafficOnly` matches regardless
of how the policy JSON capitalizes it.

**Strategy:**

1. The **alias table** defines canonical casing for each alias (typically
   camelCase for property segments).
2. The **normalizer** produces field names using canonical casing from the alias
   table.
3. The **JSON compiler** normalizes `"field"` references to canonical casing at
   compile time. A lookup against the alias table's short names (case-insensitive)
   maps the policy's field reference to the canonical short name.
4. The **VM** performs exact (case-sensitive) field lookups on the normalized
   structure.

For Rego policies, authors must use canonical casing since Rego is
case-sensitive. This is consistent with how all Rego field access works.

---

## 8. Scoping — No Cross-Type Ambiguity

Aliases are **always scoped to a single resource type** per evaluation:

1. Every Azure Policy rule targets a specific resource type via conditions like
   `"field": "type", "equals": "Microsoft.Storage/storageAccounts"`.
2. The normalizer normalizes ONE resource at a time using the normalization spec
   for THAT resource type only.
3. Two different resource types can have aliases with the same short name. They
   never appear in the same evaluation.

No collision mitigation is needed.

---

## 9. Multi-Level `[*]` (Nested Arrays)

Some aliases have nested array iteration:

```
Microsoft.Network/applicationGateways/requestRoutingRules[*].backendAddressPool.backendAddresses[*].fqdn
```

Short name: `requestRoutingRules[*].backendAddressPool.backendAddresses[*].fqdn`

The normalizer recursively flattens `properties` wrappers at each level. If
`requestRoutingRules` elements are sub-resources AND `backendAddresses` elements
are sub-resources, both get flattened.

In the JSON compiler, nested `[*]` produces nested `LoopStart`/`LoopNext`
instructions:

```
ChainedIndex { path: ["resource", "requestRoutingRules"] } → r_outer_arr
LoopStart(Any) { collection: r_outer_arr } → r_outer_elem
  ChainedIndex { root: r_outer_elem, path: ["backendAddressPool", "backendAddresses"] } → r_inner_arr
  LoopStart(Any) { collection: r_inner_arr } → r_inner_elem
    ChainedIndex { root: r_inner_elem, path: ["fqdn"] } → r_field
    ...
  LoopNext
LoopNext
```

In Rego:
```rego
some rule in input.resource.requestRoutingRules
some addr in rule.backendAddressPool.backendAddresses
addr.fqdn == "example.com"
```

---

## 10. Handling Array-Without-Suffix vs. Array-With-`[*]`

Azure aliases distinguish between referencing an array as a whole vs. iterating
over it:

| Reference | Meaning | Example |
|:----------|:--------|:--------|
| `securityRules` | The entire array value | Used in `count`, `equals []` comparisons |
| `securityRules[*]` | Each element | Used in `allOf`/`anyOf` iteration, `count` by condition |
| `securityRules[*].protocol` | A field on each element | used in per-element conditions |

The normalized structure doesn't change — `securityRules` is always an array in
`input.resource`. The difference is in how the **compiler** consumes the
reference:

| Field reference | Compiler output |
|:---------------|:----------------|
| `securityRules` | `ChainedIndex { path: ["resource", "securityRules"] }` → returns the array |
| `securityRules[*].protocol` | `ChainedIndex` → `LoopStart` → `ChainedIndex` for `protocol` |
| `count(securityRules[*])` | `ChainedIndex` → `Count` on the array |
| `count(securityRules[*], <condition>)` | `ChainedIndex` → `LoopStart(ForEach)` → evaluate condition → count matches |

---

## 11. Normalizer Algorithm (Pseudocode)

```python
def normalize(arm_resource: dict, spec: NormalizationSpec) -> dict:
    """Transform raw ARM JSON into the normalized input.resource structure."""
    result = {}

    # Rule 1 & 2: Copy root-level fields, flatten root properties
    ROOT_FIELDS = {
        "name", "type", "location", "kind", "id", "tags",
        "identity", "sku", "plan", "zones", "managedBy",
        "etag", "apiVersion"
    }
    for key, value in arm_resource.items():
        if key in ROOT_FIELDS:
            result[key] = value

    # Flatten properties into the root
    if "properties" in arm_resource:
        for key, value in arm_resource["properties"].items():
            result[key] = normalize_value(value, key, spec)

    return result


def normalize_value(value, field_path: str, spec: NormalizationSpec):
    """Normalize a value, flattening sub-resource arrays as needed."""
    if isinstance(value, list):
        if field_path in spec.sub_resource_arrays:
            # Rule 3: Flatten sub-resource array elements
            return [flatten_element(elem, field_path, spec) for elem in value]
        else:
            # Rule 4 & 6: Plain objects or primitives — pass through
            return value
    elif isinstance(value, dict):
        # Recurse into nested objects to find arrays
        return {
            k: normalize_value(v, f"{field_path}.{k}", spec)
            for k, v in value.items()
        }
    else:
        return value


def flatten_element(element: dict, array_path: str, spec: NormalizationSpec) -> dict:
    """Flatten a sub-resource array element by merging its properties."""
    if not isinstance(element, dict):
        return element

    result = {}

    # Copy non-properties fields from the element envelope
    for key, value in element.items():
        if key != "properties":
            result[key] = normalize_value(value, f"{array_path}.{key}", spec)

    # Merge properties into the element
    if "properties" in element and isinstance(element["properties"], dict):
        for key, value in element["properties"].items():
            result[key] = normalize_value(
                value, f"{array_path}.{key}", spec
            )

    return result
```

### 11.1 Deriving the normalization spec from the alias table

```python
def derive_spec(alias_table: dict, resource_type: str) -> NormalizationSpec:
    """
    Given an alias table mapping full aliases to ARM paths,
    derive the normalization spec for a resource type.
    """
    sub_resource_arrays = set()

    prefix = resource_type + "/"
    for alias, arm_path in alias_table.items():
        if not alias.startswith(prefix):
            continue

        short_name = alias[len(prefix):]

        # Look for pattern: X[*].Y in short name
        # mapping to:       properties.X[*].properties.Y in ARM path
        # The double "properties" indicates a sub-resource array
        if "[*]." in short_name:
            array_part = short_name.split("[*].")[0]  # e.g., "securityRules"
            arm_array = f"properties.{array_part}[*].properties."
            if arm_path.startswith(arm_array):
                sub_resource_arrays.add(array_part)

    return NormalizationSpec(sub_resource_arrays=sub_resource_arrays)
```

---

## 12. End-to-End Flow

```
┌────────────────────────────────────────────────────────────┐
│                      ALIAS TABLE                           │
│                                                            │
│  Microsoft.Network/networkSecurityGroups/                  │
│    securityRules[*].protocol                               │
│      → properties.securityRules[*].properties.protocol     │
│                                                            │
│  Derived normalization spec:                               │
│    sub_resource_arrays: [securityRules,                    │
│                          defaultSecurityRules]              │
└──────────────────────────┬─────────────────────────────────┘
                           │
                           ▼
┌────────────────────────────────────────────────────────────┐
│                     NORMALIZER                             │
│                                                            │
│  raw ARM resource ──→ flatten root properties              │
│                    ──→ flatten sub-resource array elements  │
│                    ──→ normalized resource                  │
│                                                            │
│  Runs ONCE per resource. Cached for all policy evals.      │
└──────────────────────────┬─────────────────────────────────┘
                           │ normalized resource
                           ▼
┌────────────────────────────────────────────────────────────┐
│                     COMPILER                               │
│                                                            │
│  "field": "securityRules[*].protocol"                      │
│                                                            │
│  1. Parse field → short name (strip type prefix if needed) │
│  2. Canonicalize casing via alias table lookup              │
│  3. Split on '.' and '[*]'                                 │
│  4. Emit ChainedIndex / LoopStart / LoopNext               │
│                                                            │
│  No alias resolution. No properties awareness.             │
│  Just path splitting.                                      │
└──────────────────────────┬─────────────────────────────────┘
                           │ RVM bytecode
                           ▼
┌────────────────────────────────────────────────────────────┐
│                        VM                                  │
│                                                            │
│  input.resource.securityRules[0].protocol → "Tcp"          │
│                                                            │
│  Zero alias awareness. Just field indexing on plain JSON.   │
└────────────────────────────────────────────────────────────┘
```

---

## 13. Open Questions

1. **Sub-resource type aliases**: Aliases like
   `Microsoft.Compute/virtualMachines/extensions/type` reference a child
   resource type (`extensions`). When evaluating the parent resource
   (`virtualMachines`), how should these appear in `input.resource`? Options:
   - The parent resource includes inline child resources (if present in the ARM
     payload), normalized under their type name.
   - Child resource aliases are only evaluated when the child resource itself is
     the evaluation target (separate `input.resource` per child).

2. **Fields not covered by aliases**: ARM resources may have fields that no
   alias exists for. These still appear in `input.resource` after root
   `properties` flattening. Should the normalizer include ALL properties fields,
   or only those with corresponding aliases?

3. **Unknown resource types**: If a resource type has no entry in the
   normalization spec, the normalizer can fall back to: (a) flatten root
   `properties` only (no sub-resource flattening), or (b) use heuristic
   detection (element has a `properties` key).

4. **Alias table packaging**: How is the alias table distributed? Options:
   - Bundled with target definitions (static, versioned)
   - Fetched from Azure at deployment time (dynamic)
   - Derived from resource schemas already in the `Target` struct
