#!/usr/bin/env python3
#**********************************************************
# Copyright (c) 2025 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
# **********************************************************

import argparse
import json
import logging
import math
import ssl
import sys

# For use in environments with self-signed certificates
IGNORE_SSL_CONTEXT = ssl.create_default_context()
IGNORE_SSL_CONTEXT.check_hostname = False
IGNORE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

from base64 import b64encode
from datetime import datetime
from getpass import getpass
from time import sleep, time
from urllib.parse import quote
from urllib.request import urlopen, Request, HTTPError

#logging.basicConfig()
logger = logging.getLogger()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setFormatter(formatter)
file_handler = logging.FileHandler(f"{__file__}-{int(time())}.log")
file_handler.setFormatter(formatter)
logger.addHandler(stdout_handler)
logger.addHandler(file_handler)
logger.setLevel(logging.INFO)

def text_prompt(prompt="> ", mask=False):
    """
    Helper function that prompts the user for input.
    Supports masking input for sensitive values.
    """
    if mask:
        return getpass(prompt)
    return input(prompt)

def menu_prompt(choices, pre_prompt="Select option", post_prompt="> "):
    """
    Helper function that presents a menu of choices to the user
    and allows them to pick exactly one option
    """
    if len(choices) == 0:
        raise Exception("No choices available")
    print(pre_prompt)
    index = 1
    for choice in choices:
        print(f"{index}. {choice}")
        index += 1
    while True:
        selection = text_prompt(post_prompt)
        try:
            as_int = int(selection)
            if as_int <= 0 or as_int > len(choices):
                raise Exception()
            break
        except:
            print("Invalid selection, please try again")
    return choices[as_int-1]

def execute_request(request, expected_statuses=[200]):
    """
    Execute a HTTP request, read and return the response.
    Log debugging information about any unexpected status
    """
    result = None
    try:
        with urlopen(request, context=IGNORE_SSL_CONTEXT) as response:
            result = response.read()
    except HTTPError as error:
        if error.code not in expected_statuses:
            error_message = error.read()
            logger.error(f"Unexpected http error {error.code} for url {error.url} Body: {error_message}")
            raise error
    return result

def execute_request_to_json(request, expected_statuses=[200]):
    """
    Execute a HTTP request, read, parse the response as JSON
    and return the resulting Python object.
    Log debugging information about any unexpected status
    """
    return json.loads(execute_request(request, expected_statuses))

class Context:
    """
    The Context class contains all the state and user input
    for the current execution of the rwr workflow.
    """
    def __init__(self):
        self._hostname = None
        self._primary_user = None
        self._primary_pass = None
        self._recovery_user = None
        self._recovery_pass = None
        self._session_id = None
        self._session_timestamp = 0
        self._pairing = None
        self._pairing_id = None
        self._replication = None
        self._replication_id = None
        self._promoted_instance = None
        self._instances = None
        self._active_image = None
        self._selected_instance = None
        self._selected_instance_id = None
        self._compute_resource = None
        self._compute_resource_id = None
        self._vm_folder = None
        self._vm_folder_id = None

    def __enter__(self):
        """
        Context Manager internals
        """
        return self

    def __exit__(self, type, value, traceback):
        """
        Context Manager internals
        """
        self.logout_from_vlr()

    def dr_url_for(self, path):
        """
        Helper function that generates URLs for calling DR REST Gateway APIs
        """
        return "https://" + self._hostname + path

    def get_dr_headers(self, auto_refresh = True):
        """
        Helper function that sets up required headers for calling DR REST Gateway APIs
        """
        if auto_refresh and (int(time()) - self._session_timestamp) > 300:
            logger.info("Token refresh required")
            self.logout_from_vlr()
            self.login_to_vlr()
            self.login_to_remote_vlr()
        headers = {
            "x-dr-session": self._session_id,
            "Content-Type": "application/json",
        }
        return headers

    def monitor_task(self, task_id):
        """
        Monitor an ongoing task through the REST gateway API
        """
        logger.info(f"Monitoring task with id {task_id}")
        while True:
            request = Request(self.dr_url_for(f"/api/rest/vr/v2/tasks/{task_id}"),
                              headers=self.get_dr_headers(),
                              method="GET")
            result = execute_request_to_json(request)
            task_status = result["status"]
            logger.info(f"Task status is {task_status}")
            if task_status == "SUCCESS":
                logger.info("Task finished successfully")
                return True
            if task_status == "ERROR":
                logger.error(f"Task failed. Task info: {result}")
                return False
            sleep(5)

    def collect_environment(self, args):
        """
        Prompts the user for hostname and login credentials of the VLR appliance
        and stores them in the context for further use
        """
        if "recoveryVlr" in args and args.recoveryVlr is not None:
            self._hostname = args.recoveryVlr
        else:
            self._hostname = text_prompt("Enter recovery VLR appliance hostname: ")

        if "primaryUser" in args and args.primaryUser is not None:
            self._primary_user = args.primaryUser
        else:
            self._primary_user = text_prompt("Enter primary vCenter username: ")

        if "primaryPassword" in args and args.primaryPassword is not None:
            self._primary_pass = args.primaryPassword
        else:
            self._primary_pass = text_prompt("Enter primary vCenter password: ", mask=True)

        if "recoveryUser" in args and args.recoveryUser is not None:
            self._recovery_user = args.recoveryUser
        else:
            self._recovery_user = text_prompt("Enter recovery vCenter username: ")

        if "recoveryPassword" in args and args.recoveryPassword is not None:
            self._recovery_pass = args.recoveryPassword
        else:
            self._recovery_pass = text_prompt("Enter recovery vCenter password: ", mask=True)

    def login_to_vlr(self):
        """
        Login to the VLR appliance, get a session token and add it to the environment.
        Other functions can then use it to call the remaining of the APIs
        """
        logger.info("Logging to recovery VR REST API Gateway")
        auth = "Basic " + b64encode((self._recovery_user + ":" + self._recovery_pass).encode()).decode()
        request = Request(self.dr_url_for("/api/rest/vr/v2/session"),
                          headers={"Authorization" : auth},
                          method="POST")
        result = execute_request_to_json(request)
        self._session_id = result["session_id"]
        self._session_timestamp = int(time())

    def login_to_remote_vlr(self):
        """
        If a pairing is selected login to the remote VLR from the pairing.
        Otherwise do nothing.
        """
        if self._pairing_id == None:
            return
        pairing_id = self._pairing_id
        logger.info("Logging to primary VR REST API Gateway")
        auth = "Basic " + b64encode((self._primary_user + ":" + self._primary_pass).encode()).decode()
        headers = self.get_dr_headers()
        headers["Authorization"] = auth
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/remote-session"),
                          headers=headers,
                          method="POST")
        execute_request(request)

    def logout_from_vlr(self):
        """
        Logout from the VLR appliance
        """
        if self._session_id == None:
            return

        logger.info("Logging out from VR REST API Gateway")
        request = Request(self.dr_url_for("/api/rest/vr/v2/session"),
                          headers=self.get_dr_headers(auto_refresh=False),
                          method="DELETE")
        execute_request(request, expected_statuses=[200, 401])
        self._session_id = None
        self._session_timestamp = 0

    def get_pairings(self):
        """
        Queries the DR REST Gateway for its known site pairings
        """
        request = Request(self.dr_url_for("/api/rest/vr/v2/pairings"),
                          headers=self.get_dr_headers(),
                          method="GET")
        result = execute_request_to_json(request)
        return result["list"]

    def select_pairing(self):
        """
        Gets the available site pairings, prompts the user to pick one
        and sets it in the environment for further operations.
        """
        pairings = self.get_pairings()
        logger.info(f"Found a total of {len(pairings)} pairings")

        choices = {}
        for pairing in pairings:
            local_vc = pairing["local_vc_server"]["name"]
            remote_vc = pairing["remote_vc_server"]["name"]
            if local_vc == remote_vc:
                # Filter out local pairings
                continue
            pairing_id = pairing["pairing_id"]
            pairing_name = f"{local_vc} -> {remote_vc} / {pairing_id}"
            choices[pairing_name] = pairing

        if len(choices) == 0:
            logger.info("No compatible pairings available")
            return False
        elif len(choices) == 1:
            logger.info("Found a single compatible pairing")
            selected_pairing_name = list(choices.keys())[0]
            selected_pairing = list(choices.values())[0]
        else:
            selected_pairing_name = menu_prompt(list(choices.keys()), pre_prompt="Select pairing:")
            selected_pairing = choices[selected_pairing_name]

        self._pairing = selected_pairing
        self._pairing_id = selected_pairing["pairing_id"]
        logger.info(f"Selected pairing {selected_pairing_name}")
        return True

    def get_replications(self, href = None, filter = None):
        """
        Gets the available replications for the selected pairing.
        Returns the full REST gateway response.
        """
        if href == None:
            pairing_id = self._pairing_id
            url = f"/api/rest/vr/v2/pairings/{pairing_id}/replications?extended_info=true&sort_by=name&order_by=asc"
            if filter:
                url += f"&filter_property=name&filter={filter}"
            url = self.dr_url_for(url)
        else:
            url = href

        request = Request(url, headers=self.get_dr_headers(), method="GET")
        return execute_request_to_json(request)

    def filter_replication(self, replication, name):
        """
        Check if a replication should be filtered out from the selection.
        """
        if replication["mpit_enabled"] == False:
            logger.warning(f"Ignoring replication {name} as it is not configured for multiple instances.")
            return True
        if replication["mpit_days"] != 0:
            logger.warning(f"Ignoring replication {name} as it is not configured for number of multiple instances.")
            return True
        if replication["type"] != "VC_TO_VC":
            logger.warning(f"Ignoring replication {name} as it is not a regular vSphere replication.")
            return True
        if "recovery_solution" not in replication or replication["recovery_solution"] == None:
            logger.warning(f"Ignoring replication {name} because of unknown recovery management.")
            return True
        if not replication["recovery_solution"].startswith("com.vmware.vcDr"):
            logger.warning(f"Ignoring replication {name} because of unsupported recovery management.")
            return True
        if "status" not in replication or "status" not in replication["status"]:
            logger.warning(f"Ignoring replication {name} because of unknown status.")
            return True
        if replication["status"]["status"] in ["RECONFIGURING", "RECOVERED", "RECOVERING", "DISK_RESIZING"]:
            replication_status = replication["status"]["status"]
            logger.warning(f"Ignoring replication {name} because of unsupported status {replication_status}.")
            return True
        return False

    def select_replication(self):
        """
        Gets the available RWR replications, prompts the user to pick one
        and sets it in the environment for further operations.
        """
        href = None
        filtered_name = ""
        while True:
            result = self.get_replications(href, filtered_name)
            replications = result["list"]
            logger.info(f"Found a total of {len(replications)} replications")

            choices = {}
            for replication in replications:
                replication_name = replication["name"]
                replication_id = replication["id"]
                choice_name = f"{replication_name} / {replication_id}"
                if self.filter_replication(replication, choice_name):
                    continue
                choices[choice_name] = replication

            next_batch = result["_meta"]["links"]["next"]
            if next_batch != None:
                choices["(Next page)"] = next_batch
            prev_batch = result["_meta"]["links"]["previous"]
            if prev_batch != None:
                choices["(Previous page)"] = prev_batch

            choices[f"(Filter by name [{filtered_name}])"] = None
            choices["(Clear filter)"] = None
            choices["(Cancel)"] = None

            selected_replication_name = menu_prompt(list(choices.keys()), pre_prompt="Select replication:")
            if selected_replication_name in ["(Next page)", "(Previous page)"]:
                href = choices[selected_replication_name]["href"]
                continue
            if selected_replication_name == "(Clear filter)":
                filtered_name = ""
                href = None # Reset any paging when changing filter
                continue
            if selected_replication_name.startswith("(Filter by name ["):
                filtered_name = text_prompt("Enter VM name fragment: ")
                href = None # Reset any paging when changing filter
                continue
            if selected_replication_name == "(Cancel)":
                return False
            selected_replication = choices[selected_replication_name]
            break

        self._replication = selected_replication
        self._replication_id = selected_replication["id"]
        logger.info(f"Selected replication {selected_replication['name']}")
        return True

    def pause_replication(self):
        """
        Pauses the selected replication. This is a precondition for a successful RwR recovery.
        """
        pairing_id = self._pairing_id
        replication_id = self._replication_id

        if self._replication["status"]["status"] == "PAUSED":
            logger.info(f"Replication {replication_id} is paused, recovery can continue")
            return

        logger.info(f"Pausing replication {replication_id}")
        url = self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/pause")
        request = Request(url,
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        self.monitor_task(result["id"])

    def get_instances(self):
        """
        Gets the available instances for the selected replication
        """
        instances = []
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        url = self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/instances?limit=200")
        while True:
            request = Request(url, headers=self.get_dr_headers(), method="GET")
            result = execute_request_to_json(request)
            instances += result["list"]
            next_batch = result["_meta"]["links"]["next"]
            if next_batch == None:
                break
            else:
                url = next_batch["href"]
        return instances

    def collect_instances(self):
        """
        Collect the available instances for the selected replication
        in the environment. Detect if a promoted instance exists and
        extracts it from the remaining ones.
        """
        replication_id = self._replication_id
        logger.info(f"Collecting instances for replication {replication_id}")
        self._promoted_instance = None
        self._instances = []
        instances = self.get_instances()
        for instance in instances:
            if instance["promoted"] == True:
                promoted_instance_id = instance["id"]
                logger.info(f"Found promoted instance {promoted_instance_id} for replication {replication_id}")
                self._promoted_instance = instance
            else:
                self._instances.append(instance)

    def active_image_exists(self):
        """
        Checks if there is an active image for the selected replication
        """
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        logger.info(f"Checking if an active image exist for replication {replication_id}")
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/active-image"),
                          headers=self.get_dr_headers(),
                          method="GET")
        response = execute_request(request, expected_statuses=[404])
        if response != None:
            result = json.loads(response)
            logger.info(f"Active image found for replication {replication_id}")
            self._active_image = result
            return True
        else:
            logger.info(f"Active image not found for replication {replication_id}")
            self._active_image = None
            return False

    def should_promote_instance(self):
        """
        Prompts the user if the active image should be made into
        a promoted instance that can be used for failover.
        """
        vm_id = self._active_image["vm_ids"][0]
        logger.info(f"Active image with vm {vm_id} found. Inspect it and decide how to proceed.")
        choices = {}
        choices["Promote active image"] = True
        choices["Remove active image"] = False
        choice_name = menu_prompt(list(choices.keys()), pre_prompt="Select action:")
        return choices[choice_name]

    def promote_instance(self):
        """
        Promotes the active image into a new promoted instance
        """
        logger.info("Promoting active image")
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        active_image_id = self._active_image["id"]
        body = f"""{{
            "value": "{active_image_id}"
        }}"""
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/promote-test-image"),
                          data=body.encode(),
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        self.monitor_task(result["id"])

    def cleanup_active_image(self):
        """
        Removes the active image
        """
        logger.info("Cleaning active image")
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        active_image_id = self._active_image["id"]
        body = f"""{{
            "value": "{active_image_id}"
        }}"""
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/cleanup"),
                          data=body.encode(),
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        self.monitor_task(result["id"])

    def promoted_instance_exists(self):
        """
        Checks if there is a promoted instance for the selected replication
        """
        return self._promoted_instance != None

    def should_demote_promoted_instance(self):
        """
        Prompts the user if a promoted instance should be demoted
        so that SRM failover can instead failover to the latest instance.
        """
        logger.info("A promoted instance already exists for this replication. Would you like to demote it ?")
        choices = {}
        choices["Demote promoted instance"] = True
        choices["Cancel"] = False
        choice_name = menu_prompt(list(choices.keys()), pre_prompt="Select action:")
        return choices[choice_name]

    def demote_promoted_instance(self):
        """
        Demotes a previously promoted instance so that so that when
        a failover occurs it will default to the latest instance instead.
        """
        logger.info("Demoting promoted instance")
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/demote-test-image"),
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        self.monitor_task(result["id"])

    def select_instance(self):
        """
        Gets the available instances, prompts the user to pick one
        and sets it in the environment for further operations.
        """

        def to_human_readable_size(bytes):
            if bytes == 0:
                return "0B"
            units = ("B", "KB", "MB", "GB", "TB", "PB")
            i = int(math.floor(math.log(bytes, 1024)))
            p = math.pow(1024, i)
            s = round(bytes / p, 2)
            return "%s %s" % (s, units[i])

        choices = {}
        for instance in self._instances:
            timestamp = instance["transfer_start_time"] / 1000
            date = datetime.fromtimestamp(timestamp)
            id = instance["id"]
            readable_size = to_human_readable_size(instance["transfer_bytes"])
            name = f"{date} ({readable_size}) / {id}"
            choices[name] = instance

        if len(choices) == 0:
            logger.error("No compatible instances available")
            return False
        elif len(choices) == 1:
            logger.info("Found a single compatible instance")
            selected_instance_name = list(choices.keys())[0]
            selected_instance = list(choices.values())[0]
        else:
            choices["(Cancel)"] = None
            selected_instance_name = menu_prompt(list(choices.keys()), pre_prompt="Select instance:")
            if selected_instance_name == "(Cancel)":
                return False
            selected_instance = choices[selected_instance_name]

        self._selected_instance = selected_instance
        self._selected_instance_id = selected_instance["id"]
        logger.info(f"Selected instance {selected_instance_name}")
        return True

    def get_compute_resources(self, path="/"):
        """
        Query the REST Gateway for compute resources on the local VC of the selected pairing
        """
        pairing_id = self._pairing_id
        vcenter_id = self._pairing["local_vc_server"]["id"]
        escaped_path = quote(path)
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/vcenters/{vcenter_id}/inventory/compute?path={escaped_path}&limit=200"),
                          headers=self.get_dr_headers(),
                          method="GET")
        result = execute_request_to_json(request)
        return result["list"]

    def select_compute_resource(self):
        """
        Gets the available compute resource, prompts the user to pick one
        and sets it in the environment for further operations.
        """
        logger.info("Selecting compute resource")
        pathStack = ["/"]
        while True:
            resources = self.get_compute_resources(pathStack[-1])
            choices = {}
            for resource in resources:
                name = resource["name"]
                id = resource["id"]
                if resource["id"].startswith("HostSystem") \
                        or resource["id"].startswith("ResourcePool") \
                        or resource["id"].startswith("ClusterComputeResource"):
                    select_choice_name = f"(Select) {name} / {id}"
                    select_choice = {"resource" : resource, "type" : "compute"}
                    choices[select_choice_name] = select_choice
                if resource["id"].startswith("Datacenter") \
                        or resource["id"].startswith("Folder") \
                        or resource["id"].startswith("ClusterComputeResource"):
                    descent_choice_name = f"(Descent) {name} / {id}"
                    descent_choice = {"resource" : resource, "type" : "descend"}
                    choices[descent_choice_name] = descent_choice

            if len(pathStack) > 1:
                choices["(Ascend)"] = {"type" : "ascend"}

            choices["(Cancel)"] = None
            choice_name = menu_prompt(list(choices.keys()), pre_prompt="Select compute resource:")
            if choice_name == "(Cancel)":
                return False
            if choices[choice_name]["type"] == "compute":
                self._compute_resource = choices[choice_name]["resource"]
                self._compute_resource_id = choices[choice_name]["resource"]["id"]
                break
            if choices[choice_name]["type"] == "descend":
                pathStack.append(choices[choice_name]["resource"]["path"])
            if choices[choice_name]["type"] == "ascend":
                pathStack.pop()
        logger.info(f"Selected compute resource {self._compute_resource_id}")
        return True

    def get_folders(self, path="/"):
        """
        Query the REST Gateway for VM folders on the local VC of the selected pairing
        """
        pairing_id = self._pairing_id
        vcenter_id = self._pairing["local_vc_server"]["id"]
        escaped_path = quote(path)
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/vcenters/{vcenter_id}/inventory/vm-folder?path={escaped_path}"),
                          headers=self.get_dr_headers(),
                          method="GET")
        result = execute_request_to_json(request)
        return result["list"]

    def select_folder(self):
        """
        Gets the available folders, prompts the user to pick one
        and sets it in the environment for further operations.
        """
        pathStack = ["/"]
        while True:
            folders = self.get_folders(pathStack[-1])
            choices = {}
            for folder in folders:
                name = folder["name"]
                id = folder["id"]
                select_choice_name = f"(Select) {name} / {id}"
                select_choice = {"folder" : folder, "type" : "compute"}
                descent_choice_name = f"(Descent) {name} / {id}"
                descent_choice = {"folder" : folder, "type" : "descend"}
                choices[select_choice_name] = select_choice
                choices[descent_choice_name] = descent_choice

            if len(pathStack) > 1:
                choices["(Ascend)"] = {"type" : "ascend"}

            choices["(Cancel)"] = None
            choice_name = menu_prompt(list(choices.keys()), pre_prompt="Select VM folder:")
            if choice_name == "(Cancel)":
                return False
            if choices[choice_name]["type"] == "compute":
                self._vm_folder = choices[choice_name]["folder"]
                self._vm_folder_id = choices[choice_name]["folder"]["id"]
                break
            if choices[choice_name]["type"] == "descend":
                pathStack.append(choices[choice_name]["folder"]["path"])
            if choices[choice_name]["type"] == "ascend":
                pathStack.pop()
        logger.info(f"Selected vm folder resource {self._vm_folder_id}")
        return True

    def perform_test_recovery(self):
        """
        Performs a test recovery operation creating a VM from the selected instance.
        The VM info is stored in the environment for further operations
        """
        logger.info("Performing test recovery")
        pairing_id = self._pairing_id
        replication_id = self._replication_id
        instance_id = self._selected_instance_id
        folder_id = self._vm_folder_id
        compute_resource_id = self._compute_resource_id
        body = f"""{{
        "instance_id": "{instance_id}",
        "folder_id": "{folder_id}",
        "compute_resource_id": "{compute_resource_id}",
        "excluded_disk_backings": null,
        "power_on": "false"
        }}"""
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/test"),
                          data=body.encode(),
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        if self.monitor_task(result["id"]):
            logger.info(f"Created test vm with name {self._replication['name']}-test-vm")

    def should_repeat_recovery(self):
        """
        Asks for confirmation if the recovery workflow should repeat
        """
        choices = {}
        choices["Repeat recovery workflow"] = True
        choices["Leave recovery workflow"] = False
        choice_name = menu_prompt(list(choices.keys()), pre_prompt="Select action:")
        return choices[choice_name]
        pass

def setup_arguments():
    """
    Perform argument parsing and return the result
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--recoveryVlr', type=str, help='Recovery VLR appliance hostname')
    parser.add_argument('--primaryUser', type=str, help='Primary vCenter username')
    parser.add_argument('--primaryPassword', type=str, help='Primary vCenter password')
    parser.add_argument('--recoveryUser', type=str, help='Recovery vCenter username')
    parser.add_argument('--recoveryPassword', type=str, help='Recovery vCenter Password')
    return parser.parse_args()

def main():
    args = setup_arguments()
    try:
        with Context() as ctx:
            ctx.collect_environment(args)
            while True:
                if not ctx.select_pairing():
                    break
                ctx.login_to_remote_vlr()
                if not ctx.select_replication():
                    break
                ctx.pause_replication()
                while True:
                    ctx.collect_instances()
                    if ctx.promoted_instance_exists():
                        if ctx.should_demote_promoted_instance():
                            ctx.demote_promoted_instance()
                        break
                    if ctx.active_image_exists():
                        if ctx.should_promote_instance():
                            ctx.promote_instance()
                        else:
                            ctx.cleanup_active_image()
                        break
                    if not ctx.select_instance():
                        break
                    if not ctx.select_compute_resource():
                        continue
                    if not ctx.select_folder():
                        continue
                    ctx.perform_test_recovery()
                if not ctx.should_repeat_recovery():
                    break
    except (KeyboardInterrupt, SystemExit, EOFError):
        logger.info("Exiting recovery workflow")

if __name__ == "__main__":
    main()
