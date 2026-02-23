# Policy Test Lockdown – Todo

Policies selected for e2e lockdown based on `scripts/analyze_policies.py` analysis
of 4,861 policies in regolator (Feb 2026).

## Selection criteria

- **Feature gaps**: features used by real policies but not covered by any existing test
- **Large policies**: high condition-node count or line count → register overflow risk
- **Rare features**: low prevalence patterns that are compiler edge cases

## Policies to lock down

| # | Test name | Regolator file | Score | Nodes | Lines | Rationale |
|---|-----------|---------------|-------|-------|-------|-----------|
| 1 | `e2e_azupdate_scheduled_patching` | `Azure Update Manager/AzUpdateMgmtCenter_ScheduledPatching_DINE.json` | 105.6 | 231 | 1331 | Largest policy in corpus. Register overflow stress test. Value count, current(), deep nesting. |
| 2 | `e2e_azupdate_crp_autoassess_modify` | `Azure Update Manager/AzUpdateMgmtCenter_CRP_AutoAssessmentMode_Modify.json` | 87.2 | 214 | 1031 | Conditional modify ops, dynamic fields, 12+ fields. Plugs modify_ops + cond_modify + nodes_100+ gaps. |
| 3 | `e2e_asc_internet_traffic_firewall` | `Network/ASC_All_Internet_traffic_should_be_routed_via_Azure_Firewall.json` | 61.0 | 2 | ? | Count in existenceCondition (503-policy gap). Value count, nested count, doubly-nested wildcard. |
| 4 | `e2e_signalr_public_network_modify` | `SignalR/PublicNetworkAccessDisabled_Modify.json` | 37.7 | ? | ? | Multi-modify (4 operations). Only 4 policies have 3+ modify ops. |
| 5 | `e2e_automanage_deployv2` | `Automanage/Deployv2.json` | 55.5 | 106 | 638 | Broad 106-node policy, depth 4. Different register pressure shape (wide not deep). |
| 6 | `e2e_dcra_vmss_linux_dine` | `Monitoring/AzureMonitor_DCRA_VMSS_Linux_DINE.json` | 45.4 | 78 | 611 | Representative of ~30 Monitoring/* policies at 50-90 nodes. |
| 7 | `e2e_ssh_security_baseline_dine` | `Guest Configuration/LinuxSshServerSecurityBaseline_DINE.json` | 48.7 | 51 | 910 | 4th largest by line count (910 lines). 10+ fields. |
| 8 | `e2e_fic_github_issuer` | `Managed Identity/FIC_LimitToGitHubIssuer.json` | 46.1 | 10 | 98 | Value count variant (not KV shape). |
| 9 | `e2e_shared_dashboard_deny` | `Portal/SharedDashboardInlineContent_Deny.json` | 46.0 | 2 | 86 | Doubly-nested wildcard with field count in a deny. |

## Feature gap coverage

| Feature Gap | Prevalence | Covered by |
|-------------|-----------|------------|
| `modify_ops` (0/99) | 2.0% | #2 (AzUpdate CRP), #4 (SignalR) |
| `cond_modify` (0/56) | 1.2% | #2 (AzUpdate CRP) |
| `multi_modify` (0/4) | <0.1% | #4 (SignalR) |
| `count_in_ec` (0/503) | 10.3% | #3 (ASC Internet traffic) |
| `nodes_100+` (0/8) | 0.2% | #1 (ScheduledPatching), #2 (CRP), #5 (Automanage) |

## Status

- [ ] #1 `e2e_azupdate_scheduled_patching`
- [ ] #2 `e2e_azupdate_crp_autoassess_modify`
- [ ] #3 `e2e_asc_internet_traffic_firewall`
- [ ] #4 `e2e_signalr_public_network_modify`
- [ ] #5 `e2e_automanage_deployv2`
- [ ] #6 `e2e_dcra_vmss_linux_dine`
- [ ] #7 `e2e_ssh_security_baseline_dine`
- [ ] #8 `e2e_fic_github_issuer`
- [ ] #9 `e2e_shared_dashboard_deny`
