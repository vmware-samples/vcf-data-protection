# requires python 3

# Copyright (c) 2023-2025 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

from enum import Enum, IntEnum

# Default domain to work with for RWR policies.
POLICY_DOMAIN = "default"

# APIs
BASE_API = "https://{hostname}"
NODE_API = BASE_API + "/api/v1/node"
POLICY_BASE_API = BASE_API + "/policy/api/v1"
POLICY_SEARCH_BASE_API = POLICY_BASE_API + "/search?query="
POLICY_INFRA_BASE_API = POLICY_BASE_API + "/infra"
REALIZED_STATE_VIRTUAL_MACHINE_API = POLICY_INFRA_BASE_API + "/realized-state/virtual-machines"
INFRA_SERVICES_URL = POLICY_INFRA_BASE_API + "/services"
INFRA_CONTEXT_PROFILES_URL = POLICY_INFRA_BASE_API + "/context-profiles"
INFRA_CONTEXT_CUSTOM_ATTRIBUTES_URL = INFRA_CONTEXT_PROFILES_URL + "/custom-attributes/default"
SECURITY_POLICY_API = POLICY_INFRA_BASE_API + "/domains/" + POLICY_DOMAIN + "/security-policies"
GATEWAY_POLICY_URL = POLICY_INFRA_BASE_API + "/domains/" + POLICY_DOMAIN + "/gateway-policies"

DEFAULT_DESCRIPTION = "Auto-created for RWR isolation"

# IRE network isolation constants

BASE_PREFIX = "OnPrem-RWR"
POLICY_PREFIX = BASE_PREFIX + "-Policy"
RULE_PREFIX = BASE_PREFIX + "-Rule"

ONPREM_ISOLATED_PREFIX = BASE_PREFIX + "-Isolation"

ISOLATED_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Isolated-VMs"
ISOLATED_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Isolated"

QUARANTINED_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Quarantined-VMs"
QUARANTINED_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Quarantined"

QUARANTINED_ANALYSIS_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Quarantined-analysis-VMs"
QUARANTINED_ANALYSIS_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Quarantined-analysis"

EXTERNAL_OUTBOUND_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-External-Outbound-VMs"
EXTERNAL_OUTBOUND_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-External-Outbound"

INTERNAL_INBOUND_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-Inbound-VMs"
INTERNAL_INBOUND_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-Inbound"

INTERNAL_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-VMs"
INTERNAL_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Internal"

INTERNAL_PLUS_EXTERNAL_OUTBOUND_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-All-External-Outbound-VMs"
INTERNAL_PLUS_EXTERNAL_OUTBOUND_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-All-External-Outbound"

OPEN_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Open-VMs"
OPEN_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Open"

COMMON_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Common"
INTERNAL_ALL_VMS_GROUP_NAME = ONPREM_ISOLATED_PREFIX + "-Internal-All-VMs"

TIER1_GATEWAY_RWR_POLICY_FORMAT = ONPREM_ISOLATED_PREFIX + "GatewayPolicy-tier1-{tier1Id}"

# Cloud Security Analyze(CSA) related constants
CSA_ACCESS_GROUP_TAG_NAME = ONPREM_ISOLATED_PREFIX + "-Cloud-Security-Analyze-VMs"

CSA_POLICY_NAME = ONPREM_ISOLATED_PREFIX + "-Cloud-Security-Analyze"
CSA_CONTEXT_PROFILE_NAME = ONPREM_ISOLATED_PREFIX + "-Cloud-Security-Analyze-Profile"

# Ref: https://techdocs.broadcom.com/us/en/carbon-black/cloud/carbon-black-cloud-sensors/index/cbc-sensor-installation-guide-tile/GUID-8DD05446-4094-4019-AA0C-D2ED1CB15FC0-en/GUID-61DE771E-ADE8-42C4-8A20-CDAA85429C8A-en/GUID-00C9E31C-0E10-4291-ADF3-B6D457F6AE45-en.html
CBC_BACKUP_TCP_PORT = 54443
CBC_BACKUP_SERVICE_NAME = ONPREM_ISOLATED_PREFIX + "-CBC-Failback-TcpPort"

# Ref: https://techdocs.broadcom.com/us/en/carbon-black/cloud/carbon-black-cloud-sensors/index/cbc-sensor-installation-guide-tile/GUID-8DD05446-4094-4019-AA0C-D2ED1CB15FC0-en/firewallconfig.html
CBC_CUSTOM_DOMAINS_LIST = [
    "*.carbonblack.io",
    "*.confer.net",
    "*.conferdeploy.net",
    "*.cbdtest.io"
]

CROWD_STRIKE_CUSTOM_DOMAINS_LIST = [
    "*.crowdstrike.com",
    "*.crowdstrike.mil",
    "*.cloudsink.net"
]

# All RWR created groups, policies, and rules are defined in this scope
RWR_TAG_SCOPE = BASE_PREFIX + "-System-Scope"

# Rule names shared by DFW policies above and CGW rules.
OUTBOUND_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Outbound-Allow"
INTERNAL_INBOUND_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Internal-Inbound-Allow"
INTERNAL_OUTBOUND_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Internal-Outbound-Allow"
INTERNAL_OUTBOUND_DROP_RULE = ONPREM_ISOLATED_PREFIX + "-Internal-Outbound-Drop"
OUTBOUND_DROP_RULE = ONPREM_ISOLATED_PREFIX + "-Outbound-Drop"
INBOUND_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Inbound-Allow"
INBOUND_DROP_RULE = ONPREM_ISOLATED_PREFIX + "-Inbound-Drop"
OUTBOUND_DHCP_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Outbound-DHCP-Allow"
INBOUND_DHCP_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Inbound-DHCP-Allow"
DHCP_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-DHCP-Allow"
DNS_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-DNS-Allow"
COMMON_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-Common-Allow"
CSA_OUTBOUND_ALLOW_RULE = ONPREM_ISOLATED_PREFIX + "-CSA-Allow"

"""
Level of VM network isolation.

    1. ISOLATED

        Isolated from north-south and east-west traffic in On-Prem IRE.

    2. QUARANTINED

        With this isolation level, the VM is quarantined from the network. This allows the following network flows:
        DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync.
        Access to Carbon Black/Crowd Strike cloud services is NOT allowed.

    3. QUARANTINED_ANALYSIS

        With this isolation level, the VM is quarantined from the network. This allows the following network flows:
        DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync.
        Access to Carbon Black/Crowd Strike cloud services, requires NSX advanced firewall to be enabled.

    4. EXTERNAL_OUTBOUND

        Outbound access from On-Prem IRE is allowed, but isolated for east-west traffic within the IRE.
        In addition, DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync are allowed.
        Access to Carbon Black/Crowd Strike cloud services, requires NSX advanced firewall to be enabled.

    5. INTERNAL_INBOUND

        Inbound access to VM is allowed for east-west traffic within the tier-1 gateway. Internal outbound
        and all external access is blocked.
        In addition, DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync are allowed.
        Access to Carbon Black/Crowd Strike cloud services, requires NSX advanced firewall to be enabled.

    6. INTERNAL

        Access to VM is allowed for east-west traffic within the tier-1 gateway. External outbound and inbound is blocked.
        In addition, DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync are allowed.
        Access to Carbon Black/Crowd Strike cloud services, requires NSX advanced firewall to be enabled.

    7. INTERNAL_PLUS_EXTERNAL_OUTBOUND

        Access to VM is allowed for east-west traffic within the tier-1 gateway. Also, allows outbound access from IRE.
        In addition, DHCP for IP addresses, DNS traffic for name resolution, and NTP for time sync are allowed.
        Access to Carbon Black/Crowd Strike cloud services, requires NSX advanced firewall to be enabled.

    8. OPEN

        Access is allowed for both north-south and east-west traffic in On-Prem IRE.
"""

class NetworkIsolationLevel(IntEnum):
    ISOLATED = 1
    QUARANTINED = 2
    QUARANTINED_ANALYSIS = 3
    EXTERNAL_OUTBOUND = 4
    INTERNAL_INBOUND = 5
    INTERNAL = 6
    INTERNAL_PLUS_EXTERNAL_OUTBOUND = 7
    OPEN = 8

ISOLATION_LEVEL_TO_TAG_NAME_MAP = {
    NetworkIsolationLevel.ISOLATED: ISOLATED_GROUP_TAG_NAME,
    NetworkIsolationLevel.QUARANTINED: QUARANTINED_GROUP_TAG_NAME,
    NetworkIsolationLevel.QUARANTINED_ANALYSIS: QUARANTINED_ANALYSIS_GROUP_TAG_NAME,
    NetworkIsolationLevel.EXTERNAL_OUTBOUND: EXTERNAL_OUTBOUND_GROUP_TAG_NAME,
    NetworkIsolationLevel.INTERNAL_INBOUND: INTERNAL_INBOUND_GROUP_TAG_NAME,
    NetworkIsolationLevel.INTERNAL: INTERNAL_GROUP_TAG_NAME,
    NetworkIsolationLevel.INTERNAL_PLUS_EXTERNAL_OUTBOUND: INTERNAL_PLUS_EXTERNAL_OUTBOUND_GROUP_TAG_NAME,
    NetworkIsolationLevel.OPEN: OPEN_GROUP_TAG_NAME
}
