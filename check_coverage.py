import json

with open('tests/azure_policy/aliases/test_aliases.json') as f:
    data = json.load(f)

types = set()
aliases = []
for entry in data:
    ns = entry['namespace']
    for rt in entry.get('resourceTypes', []):
        rtype = f"{ns}/{rt['resourceType']}"
        types.add(rtype)
        for alias in rt.get('aliases', []):
            aliases.append(alias['name'])

print("=== Resource Types ===")
for t in sorted(types):
    print(f"  {t}")
print(f"\nTotal aliases: {len(aliases)}")

needed = {
    'VMSkusAllowed': ['Microsoft.Compute/virtualMachines/sku.name'],
    'DoubleEncryption': ['Microsoft.Compute/diskEncryptionSets/encryptionType'],
    'VMRequireManagedDisk': [
        'Microsoft.Compute/virtualMachines/osDisk.uri',
        'Microsoft.Compute/VirtualMachineScaleSets/osDisk.vhdContainers',
        'Microsoft.Compute/VirtualMachineScaleSets/osdisk.imageUrl',
    ],
    'StorageVnetRules': [
        'Microsoft.Storage/storageAccounts/networkAcls.defaultAction',
        'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]',
    ],
    'AKS_ZoneRedundant': [
        'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*]',
        'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*].availabilityZones[*]',
        'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*].count',
    ],
}

alias_set = set(a.lower() for a in aliases)
print("\n=== Alias Coverage for 5 Ready Policies ===")
for policy, needs in needed.items():
    print(f"\n{policy}:")
    for n in needs:
        found = n.lower() in alias_set
        print(f"  {'OK' if found else 'MISSING'}: {n}")
