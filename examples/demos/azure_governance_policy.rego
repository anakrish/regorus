package azure_governance

import rego.v1

allowed_regions := {"eastus", "westus2", "westeurope"}

# Allow if all conditions pass
allow if {
	region_allowed
	d_series_has_cost_center
	no_public_ip_if_internal
	production_min_size
	dev_test_nic_cap
}

# VM must be in an allowed region
region_allowed if {
	input.vm.region in allowed_regions
}

# D-series VMs require cost_center tag on the resource group
d_series_has_cost_center if {
	startswith(input.vm.size, "Standard_D")
	input.resource_group.tags.cost_center != ""
}

d_series_has_cost_center if {
	not startswith(input.vm.size, "Standard_D")
}

# Public IP blocked when resource group is tagged internal_only: true
no_public_ip_if_internal if {
	input.resource_group.tags.internal_only == true
	input.vm.public_ip == false
}

no_public_ip_if_internal if {
	not input.resource_group.tags.internal_only == true
}

# Production resource groups only allow D4 or above
production_min_size if {
	input.resource_group.tags.environment == "production"
	startswith(input.vm.size, "Standard_D")
	size_suffix := trim_prefix(input.vm.size, "Standard_D")
	num_str := regex.find_all_string_submatch_n(`^(\d+)`, size_suffix, 1)
	d_number := to_number(num_str[0][1])
	d_number >= 4
}

production_min_size if {
	not input.resource_group.tags.environment == "production"
}

# Dev/test resource groups cap NICs at 2
dev_test_nic_cap if {
	input.resource_group.tags.environment in {"dev", "test"}
	input.vm.nic_count <= 2
}

dev_test_nic_cap if {
	not input.resource_group.tags.environment in {"dev", "test"}
}
