package azure_governance

default allow := false

# Allowed regions for all VMs.
allowed_regions := {"eastus", "westus2", "westeurope"}

# Rule 1: VM must be in an allowed region.
region_ok if {
    input.vm.region == allowed_regions[_]
}

# Rule 2: D-series VMs require cost_center tag on the resource group.
cost_center_ok if {
    not startswith(input.vm.size, "Standard_D")
}

cost_center_ok if {
    startswith(input.vm.size, "Standard_D")
    input.resource_group.tags.cost_center
}

# Rule 3: No public IP if resource group is tagged internal_only: true.
public_ip_ok if {
    not input.resource_group.tags.internal_only
}

public_ip_ok if {
    input.resource_group.tags.internal_only == true
    input.vm.public_ip == false
}

# Rule 4: Production resource groups only allow D4 or larger.
# Extract the number after "Standard_D" and before the next non-digit.
production_size_ok if {
    input.resource_group.tags.environment != "production"
}

production_size_ok if {
    input.resource_group.tags.environment == "production"
    size := input.vm.size
    startswith(size, "Standard_D")
    suffix := substring(size, count("Standard_D"), -1)
    d_number := to_number(regex.find_all_string_submatch_n(`^(\d+)`, suffix, 1)[0][1])
    d_number >= 4
}

# Rule 5: Dev/test resource groups cap NIC count at 2.
nic_count_ok if {
    not input.resource_group.tags.environment in {"dev", "test"}
}

nic_count_ok if {
    input.resource_group.tags.environment in {"dev", "test"}
    input.vm.nic_count <= 2
}

# All checks must pass.
allow if {
    region_ok
    cost_center_ok
    public_ip_ok
    production_size_ok
    nic_count_ok
}
