import json
with open('tests/azure_policy/aliases/test_aliases.json') as f:
    data = json.load(f)
needed = [
    'Microsoft.Compute/virtualMachines/sku.name',
    'Microsoft.Compute/diskEncryptionSets/encryptionType',
    'Microsoft.Compute/virtualMachines/osDisk.uri',
    'Microsoft.Compute/VirtualMachineScaleSets/osDisk.vhdContainers',
    'Microsoft.Compute/VirtualMachineScaleSets/osdisk.imageUrl',
    'Microsoft.Storage/storageAccounts/networkAcls.defaultAction',
    'Microsoft.Storage/storageAccounts/networkAcls.ipRules[*]',
    'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*]',
    'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*].availabilityZones[*]',
    'Microsoft.ContainerService/managedClusters/agentPoolProfiles[*].count',
]
found = set()
for ns in data:
    for rt in ns.get('resourceTypes', []):
        for alias in rt.get('aliases', []):
            if alias['name'] in needed:
                found.add(alias['name'])
                print("FOUND:", alias['name'], "->", alias['defaultPath'])
missing = set(needed) - found
if missing:
    for m in sorted(missing):
        print("MISSING:", m)
else:
    print("All aliases found!")
