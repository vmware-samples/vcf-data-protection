#!/usr/bin/env python
# requires python 3

# Copyright (c) 2023-2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

from constants import *
from typing import Optional

import argparse
import base64
import logging
import json
import ssl
import time
import urllib.request
import urllib.error
import pprint
import sys
import time

pp = pprint.PrettyPrinter()
class NsxtServiceClient(object):
    """
    Class that provides NSX-T Services.
    """

    def __init__(self, hostname: str, user: str, password: str, logger) -> None:
        """
        Establishes a client connection to the passed NSX Manager.
        :param hostname: NSX-T hostname.
        :param user: NSX MP admin user.
        :param password: NSX MP admin user password.
        :param logger: Logger to use from logging module
        :return: None
        """
        self._hostname = hostname
        self._user = user
        self._password = password
        self.logger = logger

    def __get_nsx_api_headers(self, json_content_type_header=False) -> dict:
        """
        Get NSX api headers
        :return: API headers.
        """
        credentials = ('%s:%s' % (self._user, self._password))
        encoded_credentials = base64.b64encode(credentials.encode('utf-8'))
        headers = {
            'Authorization': 'Basic %s' % encoded_credentials.decode("utf-8")
        }
        if json_content_type_header:
            headers['Content-type'] = 'application/json'
        return headers

    @staticmethod
    def __get_nsx_api_ssl_ctx() -> ssl.SSLContext:
        """
        Get NSX SSL context
        :return: API SSL context.
        """
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def __send_nsx_request(self, url: str,
                           method="GET",
                           params: {} = None,
                           **kwargs) -> (dict, dict):
        """
        Send HTTP request to target NSX-T hostname.
        :param url: target NSX-T hostname.
        :param user: NSX MP admin user.
        :param password: NSX MP admin user password.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        :raises:
            Exception: In case of any HTTP error returned as result or other connection error.
        """
        req = urllib.request.Request(url,
                                     method=method,
                                     headers=self.__get_nsx_api_headers(bool(method != "GET")),
                                     data=json.dumps(params).encode("utf8") if params else None)

        try:
            self.logger.info("Invoking {} method on url {}".format(method, url))
            if req.data:
                self.logger.debug("Encoded request body\n%s", req.data)
            resp = urllib.request.urlopen(
                req, context=self.__get_nsx_api_ssl_ctx(), **kwargs)
            self.logger.info("HTTP Response code: {}".format(resp.status))
            if 200 >= resp.status < 300:
                decoded_data = resp.read().decode(
                    resp.info().get_content_charset('utf-8'))
                if decoded_data is None or not decoded_data:
                    response = None
                else:
                    response = json.loads(decoded_data)
                return response, None
            return None, resp
        except urllib.error.HTTPError as e:
            msg = "Exception message: HTTP Error {}: {}".format(e.code, e.read().decode())
            self.logger.error(msg)
            raise Exception(msg)
        except Exception as e:
            msg = "Exception message : {}".format(e)
            self.logger.error(msg)
            raise Exception(msg)

    def get_node_status(self) -> (dict, dict):
        """
        Check if we have connectivity to NSX.
        Returns Node info.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        get_node_status_url = NODE_API.format(hostname=self._hostname)
        return self.__send_nsx_request(url=get_node_status_url)

    def get_tier0_gateways(self) -> (dict, dict):
        """
        GET /policy/api/v1/infra/tier-0s
        Get Tier0 Gateways. Returns Tier0 gateways info.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        get_tier0_url = (POLICY_BASE_API.format(hostname=self._hostname) +
                         "/infra/tier-0s")
        return self.__send_nsx_request(url=get_tier0_url)

    def get_tier1_gateways(self) -> (dict, dict):
        """
        GET /policy/api/v1/infra/tier-1s
        Get Tier1 Gateways. Returns Tier1 gateways info.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        get_tier1_url = (POLICY_BASE_API.format(hostname=self._hostname) +
                         "/infra/tier-1s")
        return self.__send_nsx_request(url=get_tier1_url)

    def get_tier1_gateway(self, target_name: str) -> (dict, dict):
        """
        GET /policy/api/v1/search?query=resource_type:Segment%20AND%20connectivity_path:“/infra/tier-1s/
        Get Tier1 Gateway by name. Returns the found Tier1 gateway info.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        search_tier1_url = (POLICY_SEARCH_BASE_API.format(hostname=self._hostname) +
                            "resource_type:Tier1%20AND%20display_name:" + target_name)
        return self.__send_nsx_request(url=search_tier1_url)

    def get_tier1_gateway_id(self, target_tier1_name) -> str:
        """
        Get Tier1 Gateway Id by name. Returns the found Tier1 gateway ID.
        :return: The found tier1 ID.
        :raises:
            Exception: If no tier1 gateway is found for the given name or in case
                       any other connection error or HTTP error is returned as result.
        """
        response, err = self.get_tier1_gateway(target_tier1_name)
        if err is not None:
            msg = "Cannot find Tier-1 gateway with name '{}' due to error :" \
                  " '{}'".format(target_tier1_name,  pp.pformat(err))
            self.logger.error(msg)
            raise Exception(msg)
        result_count = int(response["result_count"])
        if result_count == 0:
            msg = "No Tier-1 gateway with name '%s' found.".format(target_tier1_name)
            self.logger.error(msg)
            raise Exception(msg)

        self.logger.info("Found %s Tier-1 gateway with name '%s':\n'%s'",
                         result_count, target_tier1_name, pp.pformat(response))

        tier1_gateway_id = response["results"][0]["id"]

        self.logger.info("Found Tier-1 gateway with name '%s' that has id :'%s'",
                         target_tier1_name, tier1_gateway_id)
        return tier1_gateway_id

    def get_domains(self) -> (dict, dict):
        """
        GET /policy/api/v1/infra/domains
        Get all domains from for infra.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        get_domains_url = (POLICY_INFRA_BASE_API.format(hostname=self._hostname) +
                           "/domains")
        return self.__send_nsx_request(url=get_domains_url)

    def get_groups(self, domain_name=POLICY_DOMAIN) -> (dict, dict):
        """
        GET /policy/api/v1/infra/domains/{domain}/groups
        Get all domains from for infra.
        :return: Tuple containing the dictionary result of
                 json request response and None if the request succeeds
                 else return None and error.
        """
        get_groups_url = (POLICY_INFRA_BASE_API.format(hostname=self._hostname) +
                          "/domains/" + domain_name + "/groups")
        return self.__send_nsx_request(url=get_groups_url)

    def get_group(self, target_name: str) -> (dict, dict):
        search_group_url = (POLICY_SEARCH_BASE_API.format(hostname=self._hostname) +
                            "resource_type:Group%20AND%20display_name:" + target_name)
        return self.__send_nsx_request(url=search_group_url)

    def assign_tags_to_vm(self, vm_instance_uuid: str, tags_names: [str]) -> (dict, dict):
        # TODO: This API will replace all existing tags for the target VM
        #       This may not be desirable for on-prem customers as the main ask for SRM and NSX integration is tags
        #       preservation. There should be other api for that like /api/v1/fabric/virtual-machines?action=update_tags
        assign_tags_url = (REALIZED_STATE_VIRTUAL_MACHINE_API.format(hostname=self._hostname) +
                           "/" + vm_instance_uuid +
                           "/tags")  # ?enforcement_point_path=" + RWR_ISOLATION_POLICY_ENFORCEMENT_POINT)

        tags = []
        for tag_name in tags_names:
            tags.append({"scope": RWR_TAG_SCOPE, "tag": tag_name})

        assign_tags_params = {
            "tags": tags
        }

        return self.__send_nsx_request(url=assign_tags_url, method="POST", params=assign_tags_params)

    def unassign_tags_from_vm(self, vm_instance_uuid: str):
        # TODO: This API will remove all existing tags for the target VM
        #       This may not be desirable for on-prem customers as the main ask for SRM and NSX integration is tags
        #       preservation. There should be other api for that like /api/v1/fabric/virtual-machines?action=remove_tags
        self.assign_tags_to_vm(vm_instance_uuid, [])

    def create_group(self, group_name: str, group_expression: [dict], domain_name=POLICY_DOMAIN) -> (dict, dict):
        create_group_url = (POLICY_INFRA_BASE_API.format(hostname=self._hostname) +
                     "/domains/" + domain_name + "/groups/" + group_name)

        create_group_params = {
            "display_name": group_name,
            "description": DEFAULT_DESCRIPTION,
            "expression": group_expression
        }

        return self.__send_nsx_request(url=create_group_url, method="PATCH", params=create_group_params)

    def create_tag_group(self, group_name: str, domain_name=POLICY_DOMAIN) -> (dict, dict):
        tag_name = group_name
        return self.create_group(
            group_name,
            group_expression=[
                {
                    "member_type": "VirtualMachine",
                    "key": "Tag",
                    "operator": "CONTAINS",
                    "resource_type": "Condition",
                    "value": "%s|%s" % (RWR_TAG_SCOPE, tag_name),
                    "tags": [{"scope": RWR_TAG_SCOPE, "tag": tag_name}]
                }
            ],
            domain_name=domain_name)

    def create_all_vms_group(self, group_name: str, domain_name=POLICY_DOMAIN) -> (dict, dict):
        tag_name = group_name
        return self.create_group(
            group_name,
            # define condition to match all existing VMs.
            group_expression=[
                {
                    "member_type": "VirtualMachine",
                    "key": "Name",
                    "operator": "NOTEQUALS",
                    "resource_type": "Condition",
                    "value": "NEVER_USED_VM_NAME"
                }
            ],
            domain_name=domain_name)

    def create_isolation_groups(self) -> dict:
        self.logger.info("Creating isolation groups")

        for keys, tagName in ISOLATION_LEVEL_TO_TAG_NAME_MAP.items():
            self.create_tag_group(group_name=tagName)

        self.create_tag_group(CSA_ACCESS_GROUP_TAG_NAME)
        self.create_all_vms_group(INTERNAL_ALL_VMS_GROUP_NAME)

        # Get all created isolation groups and build the result id -> path map
        response, err = self.get_group(target_name="%s*" % BASE_PREFIX)
        if err is not None:
            self.logger.error("Cannot find RWR isolation groups just after creation:\n%s",
                              pp.pformat(err))
            sys.exit(1)

        result_count = int(response["result_count"])
        if result_count == 0:
            self.logger.error("No RWR isolation groups found just after creation.")
            sys.exit(1)

        result = {group["id"]: group["path"] for group in response["results"]}
        return result

    def create_l4_port_service(self, service_id: str, protocol: str, port: int) -> None:
        self.logger.info("Creating L4 port service needed for defining access policies")

        service_url = (INFRA_SERVICES_URL.format(hostname=self._hostname) +
                       "/" + service_id)

        patch_service_params = {
            "display_name": service_id,
            "description": DEFAULT_DESCRIPTION,
            "service_entries": [
                {
                    "id": service_id,
                    "resource_type": "L4PortSetServiceEntry",
                    "display_name": service_id,
                    "destination_ports": [
                        port
                    ],
                    "l4_protocol": protocol
                }
            ]
        }

        return self.__send_nsx_request(url=service_url, method="PATCH", params=patch_service_params)

    def get_services_paths(self, target_services_ids: [str]) -> [str]:
        result = []
        for service_id in target_services_ids:
            get_service_url = (INFRA_SERVICES_URL.format(hostname=self._hostname) + "/" + service_id)

            response, err = self.__send_nsx_request(url=get_service_url)
            if err is not None:
                self. logger.error("Cannot find service path for id '%s' due to error\n:%s",
                                   service_id, pp.pformat(err))
            elif response:
                result.append(response["path"])
                self.logger.info("Found service path: {}".format(response["path"]))
        return result

    def get_context_profile_path(self, target_profiles_id: [str]) -> [str]:
        result = []
        search_ctx_profile_url = (POLICY_SEARCH_BASE_API.format(hostname=self._hostname) +
                               "resource_type:PolicyContextProfile")
        for profile_id in target_profiles_id:
            search_ctx_profile_url += "%20AND%20id:" + profile_id

        response, err = self.__send_nsx_request(url=search_ctx_profile_url)
        if err is not None:
            self.logger.error("Cannot find context profile path for ids '%s' due to error\n:%s",
                              target_profiles_id, pp.pformat(err))
        elif response:
            result = [ctx_profile["path"] for ctx_profile in response["results"]]
            self.logger.info("Found context profile path: %s", pp.pformat(result))
        return result

    def create_csa_custom_policy_attribute(self) -> (dict, dict):
        self.logger.info("Creating Cloud Security Analyze (CSA) custom policy attributes")

        patch_custom_attr_url = (INFRA_CONTEXT_CUSTOM_ATTRIBUTES_URL.format(hostname=self._hostname))

        patch_custom_attr_params = {
           "resource_type": "PolicyCustomAttributes",
           "key": "DOMAIN_NAME",
           "value": CBC_CUSTOM_DOMAINS_LIST + CROWD_STRIKE_CUSTOM_DOMAINS_LIST,
           "datatype": "STRING",
           "attribute_source": "CUSTOM",
           "description": DEFAULT_DESCRIPTION
        }

        return self.__send_nsx_request(url=patch_custom_attr_url,
                                       method="PATCH",
                                       params=patch_custom_attr_params)

    def create_csa_custom_policy_profile(self):
        self.create_csa_custom_policy_attribute()

        self.logger.info("Creating Cloud Service Analyze (CSA) custom policy profile")

        # Create context profiles defined by domain (FQDN) for Carbon Black and CrowdStrike access.
        # PATCH /policy/api/v1/infra/context-profiles/{context-profile-id}

        patch_context_profile_url = (INFRA_CONTEXT_PROFILES_URL.format(
            hostname=self._hostname) + "/" + CSA_CONTEXT_PROFILE_NAME)

        patch_context_profile_params = {
            "resource_type": "PolicyContextProfile",
            "description": DEFAULT_DESCRIPTION,
            "attributes": [
               {
                    "key": "DOMAIN_NAME",
                    "value": CBC_CUSTOM_DOMAINS_LIST + CROWD_STRIKE_CUSTOM_DOMAINS_LIST,
                    "datatype": "STRING",
                    "description": DEFAULT_DESCRIPTION,
               }
            ]
        }

        return self.__send_nsx_request(url=patch_context_profile_url,
                                       method="PATCH",
                                       params=patch_context_profile_params)

    def create_security_policy(self, policy_name: str, policy_access_group_paths: [str], seq_num: int,
                               rules: [dict]):
        self.logger.info("Creating security policy: {}".format(policy_name))

        patch_security_policy_url = (SECURITY_POLICY_API.format(
            hostname=self._hostname) + "/" + policy_name)

        patch_security_policy_params = {
            "resource_type": "SecurityPolicy",
            "display_name": policy_name,
            "description": DEFAULT_DESCRIPTION,
            "category": "Application",
            "scope": policy_access_group_paths,
            "sequence_number": seq_num,
            "rules": rules
        }
        # Certain types like Labels, Security Policies (for the 'rules' attribute) and Services have special handling
        # for certain attributes in PATCH request. This behavior will not be overridden by Partial Patch.
        # For instance, specifying rules on Security policies as a part of the PATCH invocation merges the specified
        # rules with the existing rules. For full replacement of rules, PUT operation needs to be performed on the
        # Security Policy.
        #
        # And one contradicting statement from the NSX doc:
        #
        # Patch the security policy for a domain. If a security policy for the given
        # security-policy-id is not present, the object will get created and if it is
        # present it will be updated. This is a full replace.
        # Performance Note: If you want to edit several rules in a security policy
        # use this API. It will perform better than several individual rule APIs.
        # Just pass all the rules which you wish to edit as embedded rules to it.
        return self.__send_nsx_request(url=patch_security_policy_url,
                                       method="PATCH",
                                       params=patch_security_policy_params)

    def build_firewall_rule(self, rule_name: str, source_groups: [str], dest_groups: [str], dest_excluded: bool,
                            service_paths: [str], action: str, scope: [str], profile_paths: [str], seq_num: int) -> dict:
        result_fw_rule = {
            "resource_type": "Rule",
            "id": rule_name,
            "display_name": rule_name,
            "description": DEFAULT_DESCRIPTION,
            "sequence_number": seq_num,
            "destinations_excluded": dest_excluded,
            "action": action
        }
        if source_groups:
            result_fw_rule["source_groups"] = source_groups
        if scope:
            result_fw_rule["scope"] = scope
        if dest_groups:
            result_fw_rule["destination_groups"] = dest_groups
        if service_paths:
            result_fw_rule["services"] = service_paths
        if profile_paths:
            result_fw_rule["profiles"] = profile_paths

        return result_fw_rule
    def create_rwr_dfw_rules(self, groups_id_to_path: dict, common_services_paths: [str],
                             csa_services_paths: [str]) -> None:
        isolated_group_path = groups_id_to_path[ISOLATED_GROUP_TAG_NAME]
        quarantined_group_path = groups_id_to_path[QUARANTINED_GROUP_TAG_NAME]
        quarantined_analysis_group_path = groups_id_to_path[QUARANTINED_ANALYSIS_GROUP_TAG_NAME]
        external_outbound_group_path = groups_id_to_path[
            EXTERNAL_OUTBOUND_GROUP_TAG_NAME]
        internal_inbound_group_path = groups_id_to_path[
            INTERNAL_INBOUND_GROUP_TAG_NAME]
        internal_group_path = groups_id_to_path[INTERNAL_GROUP_TAG_NAME]
        internal_plus_external_outbound_group_path = groups_id_to_path[
            INTERNAL_PLUS_EXTERNAL_OUTBOUND_GROUP_TAG_NAME]
        open_group_path = groups_id_to_path[OPEN_GROUP_TAG_NAME]
        internal_all_vms_group_path = groups_id_to_path[INTERNAL_ALL_VMS_GROUP_NAME]
        csa_access_group_path = groups_id_to_path[CSA_ACCESS_GROUP_TAG_NAME]

        dhcp_svc_paths = self.get_services_paths([
            "DHCP-Server",
            "DHCPv6_Server",
            "DHCP-Client",
            "DHCPv6_Client"
        ])

        dns_svc_paths = self.get_services_paths([
            "DNS",
            "DNS-UDP"
        ])

        # Policies are applied to mutually exclusive VM groups, so the order shouldn't matter.
        dfw_policy_sequence_min = 1

        # Order of rules within a policy is specific to more generic, since they apply to the
        # same set of VMs.
        #
        # Cloud Service Analyze access rules use FQDN filtering at DFW which feature requires specific licenses

        fw_policy_seq_num = 0

        self.create_csa_custom_policy_profile()

        dns_ctx_profile_paths = self.get_context_profile_path(["DNS"])
        csa_ctx_profile_paths = self.get_context_profile_path([CSA_CONTEXT_PROFILE_NAME])

        self.create_security_policy(
            policy_name=CSA_POLICY_NAME,
            policy_access_group_paths=[csa_access_group_path],
            seq_num=fw_policy_seq_num,
            # Since these rules use context profiles for FQDN based filtering; which uses DNS snooping to obtain mapping
            # between IP address and FQDN; it is important to keep the rules in this order: DNS rule first, followed by
            # allowlist. Also, make sure that there are no DNS allow rules before this which are not DNS context profile
            # based - that seems to prevent the correct function of the following rules.
            rules=[
                # Rule: from csa_access_group -> ANY; DNS; ALLOW
                self.build_firewall_rule(
                    rule_name=DNS_ALLOW_RULE,
                    source_groups=[csa_access_group_path],
                    scope=[csa_access_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=dns_svc_paths,
                    profile_paths=dns_ctx_profile_paths,
                    seq_num=0,
                    action="ALLOW"),
                # Rule: from csa_access_group -> ANY; HTTPS; ALLOW
                self.build_firewall_rule(
                    rule_name=CSA_OUTBOUND_ALLOW_RULE,
                    source_groups=[csa_access_group_path],
                    scope=[csa_access_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=csa_services_paths,
                    profile_paths=csa_ctx_profile_paths,
                    seq_num=1,
                    action="ALLOW")
            ])
        fw_policy_seq_num += 1

        common_group_paths = [quarantined_group_path, quarantined_analysis_group_path,
                              external_outbound_group_path, internal_inbound_group_path,
                              internal_group_path, internal_plus_external_outbound_group_path,
                              open_group_path]

        self.create_security_policy(
            policy_name=COMMON_POLICY_NAME,
            policy_access_group_paths=common_group_paths,
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from ANY -> ANY; dhcp client and server ports; ALLOW
                self.build_firewall_rule(
                    rule_name=DHCP_ALLOW_RULE,
                    source_groups=["ANY"],
                    scope=common_group_paths,
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=dhcp_svc_paths,
                    profile_paths=None,
                    seq_num=0,
                    action="ALLOW"),
                # Rule: from sourceGroups -> ANY; DNS+NTP; ALLOW
                self.build_firewall_rule(
                    rule_name=COMMON_ALLOW_RULE,
                    source_groups=common_group_paths,
                    scope=common_group_paths,
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=common_services_paths,
                    profile_paths=None,
                    seq_num=1,
                    action="ALLOW")
            ])
        fw_policy_seq_num += 1

        quarantined_groups_paths = [isolated_group_path, quarantined_group_path, quarantined_analysis_group_path]

        self.create_security_policy(
            policy_name=QUARANTINED_POLICY_NAME,
            policy_access_group_paths=quarantined_groups_paths,
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from sourceGroups -> ANY, DROP
                self.build_firewall_rule(
                    rule_name=OUTBOUND_DROP_RULE,
                    source_groups=quarantined_groups_paths,
                    scope=quarantined_groups_paths,
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="DROP"),
                # Rule: from ANY -> destGroups, DROP
                self.build_firewall_rule(
                    rule_name=INBOUND_DROP_RULE,
                    source_groups=["ANY"],
                    scope=quarantined_groups_paths,
                    dest_groups=quarantined_groups_paths,
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="DROP")
            ])
        fw_policy_seq_num += 1

        self.create_security_policy(
            policy_name=EXTERNAL_OUTBOUND_POLICY_NAME,
            policy_access_group_paths=[external_outbound_group_path],
            seq_num=fw_policy_seq_num,
            # In order to allow only external outbound, need a separate rule to
            # drop internal outbound.
            # ??? Why not single drop rule with excluding external_outbound_group for outbound ???
            rules=[
                # Rule: from sourceGroups -> destGroups, DROP
                self.build_firewall_rule(
                    rule_name=OUTBOUND_DROP_RULE,
                    source_groups=[external_outbound_group_path],
                    scope=[external_outbound_group_path],
                    dest_groups=[internal_all_vms_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="DROP"),
                # Rule: from sourceGroups -> ANY, ALLOW
                self.build_firewall_rule(
                    rule_name=OUTBOUND_ALLOW_RULE,
                    source_groups=[external_outbound_group_path],
                    scope=[external_outbound_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="ALLOW"),
                # Rule: from ANY -> destGroups, DROP
                self.build_firewall_rule(
                    rule_name=INBOUND_DROP_RULE,
                    source_groups=["ANY"],
                    scope=[external_outbound_group_path],
                    dest_groups=[external_outbound_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=2,
                    action="DROP")
            ])
        fw_policy_seq_num += 1

        self.create_security_policy(
            policy_name=INTERNAL_INBOUND_POLICY_NAME,
            policy_access_group_paths=[internal_inbound_group_path],
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from sourceGroups -> destGroups, ALLOW
                self.build_firewall_rule(
                    rule_name=INTERNAL_INBOUND_ALLOW_RULE,
                    source_groups=[internal_all_vms_group_path],
                    scope=[internal_inbound_group_path],
                    dest_groups=[internal_inbound_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="ALLOW"),
                # Rule:
                self.build_firewall_rule(
                    rule_name=OUTBOUND_DROP_RULE,
                    source_groups=[internal_inbound_group_path],
                    scope=[internal_inbound_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="DROP")
            ])
        fw_policy_seq_num += 1

        self.create_security_policy(
            policy_name=INTERNAL_POLICY_NAME,
            policy_access_group_paths=[internal_group_path],
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from sourceGroups -> destGroups, ALLOW
                self.build_firewall_rule(
                    rule_name=INTERNAL_INBOUND_ALLOW_RULE,
                    source_groups=[internal_all_vms_group_path],
                    scope=[internal_group_path],
                    dest_groups=[internal_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="ALLOW"),
                # Rule: from sourceGroups -> destGroups, ALLOW
                self.build_firewall_rule(
                    rule_name=INTERNAL_OUTBOUND_ALLOW_RULE,
                    source_groups=[internal_group_path],
                    scope=[internal_group_path],
                    dest_groups=[internal_all_vms_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="ALLOW"),
                # Rule: from sourceGroups -> destGroups, DROP
                self.build_firewall_rule(
                    rule_name=OUTBOUND_DROP_RULE,
                    source_groups=[internal_group_path],
                    scope=[internal_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=2,
                    action="DROP")
            ])
        fw_policy_seq_num += 1

        self.create_security_policy(
            policy_name=INTERNAL_PLUS_EXTERNAL_OUTBOUND_POLICY_NAME,
            policy_access_group_paths=[internal_plus_external_outbound_group_path],
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from sourceGroups -> destGroups, ALLOW
                self.build_firewall_rule(
                    rule_name=INTERNAL_INBOUND_ALLOW_RULE,
                    source_groups=[internal_all_vms_group_path],
                    scope=[internal_plus_external_outbound_group_path],
                    dest_groups=[internal_plus_external_outbound_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="ALLOW"),
                # Rule: from sourceGroups -> ANY, ALLOW
                self.build_firewall_rule(
                    rule_name=OUTBOUND_ALLOW_RULE,
                    source_groups=[internal_plus_external_outbound_group_path],
                    scope=[internal_plus_external_outbound_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="ALLOW"),
                # Rule: from ANY -> destGroups, DROP
                self.build_firewall_rule(
                    rule_name=INBOUND_DROP_RULE,
                    source_groups=["ANY"],
                    scope=[internal_plus_external_outbound_group_path],
                    dest_groups=[internal_plus_external_outbound_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=2,
                    action="DROP")
            ])
        fw_policy_seq_num += 1

        self.create_security_policy(
            policy_name=OPEN_POLICY_NAME,
            policy_access_group_paths=[internal_group_path, open_group_path],
            seq_num=fw_policy_seq_num,
            rules=[
                # Rule: from sourceGroups -> ANY, ALLOW
                self.build_firewall_rule(
                    rule_name= OUTBOUND_ALLOW_RULE,
                    source_groups=[open_group_path],
                    scope=[open_group_path],
                    dest_groups=["ANY"],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=0,
                    action="ALLOW"),
                # Rule: from ANY -> destGroups, ALLOW
                self.build_firewall_rule(
                    rule_name= INBOUND_ALLOW_RULE,
                    source_groups=["ANY"],
                    scope=[open_group_path],
                    dest_groups=[open_group_path],
                    dest_excluded=False,
                    service_paths=["ANY"],
                    profile_paths=None,
                    seq_num=1,
                    action="ALLOW")
            ])
        fw_policy_seq_num += 1

    def get_tier1_gateway_scope_path(self, tier1_gateway_id: str) -> str:
        result = None

        self.logger.info("Search tier1 gateway by id {}".format(tier1_gateway_id))
        get_tier1_gateway_url = (POLICY_SEARCH_BASE_API.format(hostname=self._hostname) +
                               "resource_type:Tier1")
        get_tier1_gateway_url += "%20AND%20id:" + tier1_gateway_id

        response, err = self.__send_nsx_request(url=get_tier1_gateway_url)
        if err is not None:
            self.logger.error("Cannot get tier1 gateway with id '%s'. Error:\n%s",
                              tier1_gateway_id, pp.pformat(err))
        elif response:
            result = response["results"][0]["path"]
            self.logger.info("Found tier1 gateway path: %s", result)
        else:
            self.logger.error("No result return for tier1 gateway with id: %s",
                              tier1_gateway_id)
        return result

    def create_gateway_policy(self, tier1_gateway_id: str, rules: [dict]) -> (dict, dict):
        # Create policy and its rules for custom tier1 compute gateway
        # A single policy is created and all tier1 isolation related rules are added under this policy.
        # This helps consolidate all related rules under a single entity.

        # Creating gateway FW rules. The rules need to be set here so
        # that connectivity can be achieved with internet uplinks. So for DNS/NTP requests coming out of
        # custom tier-1 gateways, gateway FW rules are needed to reach destination.
        policy_name = TIER1_GATEWAY_RWR_POLICY_FORMAT.format(tier1Id=tier1_gateway_id)
        self.logger.info("Creating gateway policy: {}".format(policy_name))

        patch_gateway_policy_url = (GATEWAY_POLICY_URL.format(
            hostname=self._hostname) + "/" + policy_name)

        patch_gateway_policy_params = {
            "resource_type": "GatewayPolicy",
            "display_name": policy_name,
            "description": DEFAULT_DESCRIPTION,
            "category": "LocalGatewayRules",
            "sequence_number": 1,
            "internal_sequence_number": 1,
            "stateful": True,
            "rules": rules
        }

        return self.__send_nsx_request(url=patch_gateway_policy_url,
                                       method="PATCH",
                                       params=patch_gateway_policy_params)

    def build_gateway_rules(self, tier1_gateway_id: str, groups_id_to_path: dict,
                            common_services_paths: [str], csa_services_paths: [str]) -> [dict]:
        # Build list of NSX isolation rules for Tier1 gateway.

        tier1_gateway_scope_path = self.get_tier1_gateway_scope_path(tier1_gateway_id)

        isolated_group_path = groups_id_to_path[ISOLATED_GROUP_TAG_NAME]
        quarantined_group_path = groups_id_to_path[QUARANTINED_GROUP_TAG_NAME]
        quarantined_analysis_group_path = groups_id_to_path[QUARANTINED_ANALYSIS_GROUP_TAG_NAME]
        external_outbound_group_path  = groups_id_to_path[
            EXTERNAL_OUTBOUND_GROUP_TAG_NAME]
        internal_inbound_group_path = groups_id_to_path[
            INTERNAL_INBOUND_GROUP_TAG_NAME]
        internal_group_path = groups_id_to_path[INTERNAL_GROUP_TAG_NAME]
        internal_plus_external_outbound_group_path = groups_id_to_path[
            INTERNAL_PLUS_EXTERNAL_OUTBOUND_GROUP_TAG_NAME]
        open_group_path = groups_id_to_path[OPEN_GROUP_TAG_NAME]
        internal_all_vms_group_path = groups_id_to_path[INTERNAL_ALL_VMS_GROUP_NAME]
        csa_access_group_path = groups_id_to_path[CSA_ACCESS_GROUP_TAG_NAME]

        return [
            # Rule: sourceGroups -> ANY; HTTPS; ALLOW
            self.build_firewall_rule(
                rule_name=CSA_OUTBOUND_ALLOW_RULE,
                source_groups=[csa_access_group_path],
                scope=[tier1_gateway_scope_path],
                dest_groups=["ANY"],
                dest_excluded=False,
                service_paths=csa_services_paths,
                profile_paths=None,
                seq_num=0,
                action="ALLOW"),
            # Rule: from sourceGroups -> ANY; DNS+NTP; ALLOW
            self.build_firewall_rule(
                rule_name=COMMON_ALLOW_RULE,
                source_groups=[quarantined_group_path,
                               quarantined_analysis_group_path,
                               internal_plus_external_outbound_group_path,
                               internal_group_path,
                               internal_inbound_group_path],
                scope=[tier1_gateway_scope_path],
                dest_groups=["ANY"],
                dest_excluded=False,
                service_paths=common_services_paths,
                profile_paths=None,
                seq_num=1,
                action="ALLOW"),
            # Internal rules allow traffic only within a gateway.
            # No cross gateway traffic is allowed. internalPlusExternalOutbound
            # group should block outbound traffic to VMs in other gateways. This rule is set above the rule below
            # (OutboundAllowRule) so that its checked first. That way traffic to internal VMs are dropped
            # Rule: from sourceGroups -> destGroups, DROP
            self.build_firewall_rule(
                rule_name=INTERNAL_OUTBOUND_DROP_RULE,
                source_groups=[internal_plus_external_outbound_group_path],
                scope=[tier1_gateway_scope_path],
                dest_groups=[internal_all_vms_group_path],
                dest_excluded=False,
                service_paths=["ANY"],
                profile_paths=None,
                seq_num=2,
                action="DROP"),
            # Rule: from sourceGroups -> ANY, ALLOW
            self.build_firewall_rule(
                rule_name= OUTBOUND_ALLOW_RULE,
                source_groups=[external_outbound_group_path,
                               internal_plus_external_outbound_group_path,
                               open_group_path],
                scope=[tier1_gateway_scope_path],
                dest_groups=["ANY"],
                dest_excluded=False,
                service_paths=["ANY"],
                profile_paths=None,
                seq_num=3,
                action="ALLOW"),
            # Rule: from ANY -> destGroups, ALLOW
            self.build_firewall_rule(
                rule_name= INBOUND_ALLOW_RULE,
                source_groups=["ANY"],
                scope=[tier1_gateway_scope_path],
                dest_groups=[open_group_path],
                dest_excluded=False,
                service_paths=["ANY"],
                profile_paths=None,
                seq_num=4,
                action="ALLOW"),
            # Rule: from sourceGroups -> ANY, DROP
            self.build_firewall_rule(
                rule_name=OUTBOUND_DROP_RULE,
                source_groups=[isolated_group_path,
                               quarantined_group_path,
                               quarantined_analysis_group_path,
                               internal_inbound_group_path,
                               internal_group_path],
                scope=[tier1_gateway_scope_path],
                dest_groups=["ANY"],
                dest_excluded=False,
                service_paths=["ANY"],
                profile_paths=None,
                seq_num=5,
                action="DROP"),
            # Rule: from ANY -> destGroups, DROP
            self.build_firewall_rule(
                rule_name=INBOUND_DROP_RULE,
                source_groups=["ANY"],
                scope=[tier1_gateway_scope_path],
                dest_groups=[isolated_group_path,
                             quarantined_group_path,
                             quarantined_analysis_group_path,
                             external_outbound_group_path,
                             internal_inbound_group_path,
                             internal_plus_external_outbound_group_path,
                             internal_group_path],
                dest_excluded=False,
                service_paths=["ANY"],
                profile_paths=None,
                seq_num=6,
                action="DROP")
        ]

    def create_tier1_policies_and_rules(self, groups_id_to_path: dict, common_services_paths: [str],
                                        csa_services_paths: [str], tier1_gateway_id: str) -> None:
        self.create_gateway_policy(
            tier1_gateway_id=tier1_gateway_id,
            rules=self.build_gateway_rules(tier1_gateway_id=tier1_gateway_id,
                                           groups_id_to_path=groups_id_to_path,
                                           common_services_paths=common_services_paths,
                                           csa_services_paths=csa_services_paths)
        )

    def create_isolation_policies(self, tier1_gateway_name: str) -> None:
        tier1_gateway_id = self.get_tier1_gateway_id(tier1_gateway_name)
        groups_id_to_path = self.create_isolation_groups()
        logging.info("resul groupIdToPath:\n%s", pp.pformat(groups_id_to_path))

        # Needed only for Carbon Black fail back from 443 to 54443 TCP port usage
        self.create_l4_port_service(
            service_id=CBC_BACKUP_SERVICE_NAME,
            protocol="TCP",
            port=CBC_BACKUP_TCP_PORT)

        csa_services_paths = self.get_services_paths([
            CBC_BACKUP_SERVICE_NAME,
            "HTTPS"
        ])

        common_services_paths = self.get_services_paths([
            "DNS",
            "DNS-UDP",
            "NTP"
        ])

        self.create_rwr_dfw_rules(
            groups_id_to_path, common_services_paths, csa_services_paths)
        self.create_tier1_policies_and_rules(
            groups_id_to_path, common_services_paths, csa_services_paths, tier1_gateway_id)

    def delete_service(self, service_id: str) -> None:
        self.logger.info("Deleting service: {}".format(service_id))

        service_url = (INFRA_SERVICES_URL.format(hostname=self._hostname) + "/" + service_id)
        self.__send_nsx_request(url=service_url, method="DELETE")
        return

    def delete_csa_custom_policy_attribute(self) -> None:
        self.logger.info("Deleting custom Cloud Security Analyze (CSA) policy attributes")

        custom_attr_url = (INFRA_CONTEXT_CUSTOM_ATTRIBUTES_URL.format(hostname=self._hostname) +
                           "?action=remove")

        delete_custom_attr_params = {
           "resource_type": "PolicyCustomAttributes",
           "key": "DOMAIN_NAME",
           "value": CBC_CUSTOM_DOMAINS_LIST + CROWD_STRIKE_CUSTOM_DOMAINS_LIST,
           "datatype": "STRING",
           "attribute_source": "CUSTOM",
           "description": DEFAULT_DESCRIPTION
        }

        # TODO Implement retry as it takes time for NSX to clear the reference from
        #      the just deleted profile to these attributes. The deletion may fail
        #      with bad request in such case. It's a bug in NSX but we need to handle it.
        time.sleep(5)
        self.__send_nsx_request(url=custom_attr_url, method="POST", params=delete_custom_attr_params)
        return

    def delete_csa_custom_policy_profile(self) -> None:
        self.logger.info("Deleting custom Cloud Security Analyze policy profile")

        context_profile_url = (INFRA_CONTEXT_PROFILES_URL.format(
            hostname=self._hostname) + "/" + CSA_CONTEXT_PROFILE_NAME)

        self.__send_nsx_request(url=context_profile_url, method="DELETE")
        return

    def delete_security_policy(self, policy_id: str) -> None:
        self.logger.info("Deleting security policy: {}".format(policy_id))
        delete_security_policy_url = (SECURITY_POLICY_API.format(
            hostname=self._hostname) + "/" + policy_id)

        self.__send_nsx_request(url=delete_security_policy_url, method="DELETE")
        return

    def delete_rwr_dfw_rules(self) -> None:
        self.delete_security_policy(CSA_POLICY_NAME)
        self.delete_security_policy(COMMON_POLICY_NAME)
        self.delete_security_policy(QUARANTINED_POLICY_NAME)
        self.delete_security_policy(EXTERNAL_OUTBOUND_POLICY_NAME)
        self.delete_security_policy(INTERNAL_INBOUND_POLICY_NAME)
        self.delete_security_policy(INTERNAL_POLICY_NAME)
        self.delete_security_policy(INTERNAL_PLUS_EXTERNAL_OUTBOUND_POLICY_NAME)
        self.delete_security_policy(OPEN_POLICY_NAME)
        return

    def delete_gateway_security_policies(self, tier1_gateway_id: str) -> None:
        policy_name = TIER1_GATEWAY_RWR_POLICY_FORMAT.format(tier1Id=tier1_gateway_id)
        self.logger.info("Deleting gateway policy: {}".format(policy_name))

        delete_gateway_policy_url = (GATEWAY_POLICY_URL.format(
            hostname=self._hostname) + "/" + policy_name)

        self.__send_nsx_request(url=delete_gateway_policy_url, method="DELETE")
        return

    def delete_group(self, group_id: str, domain_name=POLICY_DOMAIN) -> None:
        create_group_url = (POLICY_INFRA_BASE_API.format(hostname=self._hostname) +
                     "/domains/" + domain_name + "/groups/" + group_id)
        self.__send_nsx_request(url=create_group_url, method="DELETE")

    def delete_isolation_groups(self) -> None:
        self.logger.info("Deleting isolation groups")

        for keys, tagName in ISOLATION_LEVEL_TO_TAG_NAME_MAP.items():
            self.delete_group(group_id=tagName)
        self.delete_group(CSA_ACCESS_GROUP_TAG_NAME)
        self.delete_group(INTERNAL_ALL_VMS_GROUP_NAME)

    def delete_isolation_policies(self, tier1_gateway_name: str) -> None:
        # 1. Delete DFW rules.
        self.delete_rwr_dfw_rules()

        # 2. Delete tier1 gateways rules
        tier1_gateway_id = self.get_tier1_gateway_id(tier1_gateway_name)
        self.delete_gateway_security_policies(tier1_gateway_id)

        # 3. Delete RWR isolation groups
        self.delete_isolation_groups()

        # 4. Delete RWR specific services
        self.delete_service(CBC_BACKUP_SERVICE_NAME)

        # 5. Delete RWR specific context profiles and attributes
        self.delete_csa_custom_policy_profile()
        self.delete_csa_custom_policy_attribute()
        return

    def assign_rwr_isolation_policy_to_vms(self, vms_uuid: [str], policy_to_assign: NetworkIsolationLevel) -> None:
        # TODO - In theory an isolation group may have more than one default policy tags.
        #        for now this is not the case so get the single one group tag from our
        #        constants
        # TODO - Need to add an option to use a custom isolation policy, for now not supported
        policy_tag = ISOLATION_LEVEL_TO_TAG_NAME_MAP[policy_to_assign]
        policy_tags = [policy_tag]

        if policy_to_assign != NetworkIsolationLevel.ISOLATED and \
                policy_to_assign != NetworkIsolationLevel.QUARANTINED:
            # For all levels except fully Isolated and QUARANTINED,
            # we need to assign Cloud Security Analyze access group as well so
            # to allow outbound traffic to Carbon Black and CrowdStrike endpoints
            policy_tags.append(CSA_ACCESS_GROUP_TAG_NAME)

        for vm_uuid in vms_uuid:
            self.assign_tags_to_vm(vm_uuid, policy_tags)

    def remove_rwr_isolation_policy_from_vms(self, vms_uuid: [str], policy_to_remove: NetworkIsolationLevel) -> None:
        # TODO - More proper implementation needed. Find out all RWR related tags related to policy_to_remove to remove
        for vm_uuid in vms_uuid:
            self.unassign_tags_from_vm(vm_uuid)
