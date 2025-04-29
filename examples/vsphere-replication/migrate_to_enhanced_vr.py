#!/usr/bin/env python3
#**********************************************************
# Copyright (c) 2025 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.
# **********************************************************

import argparse
import json
import logging
import ssl
import sys


# For use in environments with self-signed certificates
IGNORE_SSL_CONTEXT = ssl.create_default_context()
IGNORE_SSL_CONTEXT.check_hostname = False
IGNORE_SSL_CONTEXT.verify_mode = ssl.CERT_NONE

from base64 import b64encode
from getpass import getpass
from time import sleep, time
from urllib.request import urlopen, Request, HTTPError

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
    and allows them to pick exactly one option.
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

try:
    from pyVim.connect import SmartConnect, Disconnect, vim, vmodl
    CHECK_ESX_VERSIONS = True
except ModuleNotFoundError as e:
    logger.warning("pyVmomi package is not available, the script will not be able "
                   "to connect to vSphere and check ESXi versions.")
    logger.warning("If ESXi hosts older than 8.0.3U3 are used migrating replications "
                   "that use MPITs and have recently had disks changed can cause "
                   "enhanced vSphere Replication to crash!")
    logger.warning("To install pyvmomi run 'python3 -m venv migrate-env; source migrate-env/bin/activate; pip3 install pyvmomi' "
                   "and run the migration script again in the same shell session.")
    logger.warning("See the --alwaysMigrateMPITs command line option for details.")
    choice = menu_prompt(["Yes", "No"], "Do you want to continue ?")
    if choice == "No":
        sys.exit()
    CHECK_ESX_VERSIONS = False

def execute_request(request, expected_statuses=[200]):
    """
    Execute a HTTP request, read and return the response.
    Log debugging information about any unexpected status.
    """
    result = None
    start_time = time()
    try:
        with urlopen(request, context=IGNORE_SSL_CONTEXT) as response:
            result = response.read()
    except HTTPError as error:
        if error.code not in expected_statuses:
            error_message = error.read()
            logger.error(f"Unexpected http error {error.code} for url {error.url} Body: {error_message}")
            raise error
    end_time = time()
    delta = end_time - start_time
    if delta <= 1.5:
        sleep(1.5 - delta) # To avoid hitting REST API gateway rate limits
    return result

def execute_request_to_json(request, expected_statuses=[200]):
    """
    Execute a HTTP request, read, parse the response as JSON
    and return the resulting Python object.
    Log debugging information about any unexpected status.
    """
    return json.loads(execute_request(request, expected_statuses))

class Context:
    """
    The Context class contains all the state and user input
    for the current exection of the rwr workflow.
    """
    def __init__(self):
        self._primaryHms = None
        self._recoveryHms = None
        self._primaryVCenterUser = None
        self._recoveryVCenterUser = None
        self._primaryPassword = None
        self._recoveryPassword = None
        self._roboMode = False
        self._session_id = None
        self._session_timestamp = 0
        self._pairing = None
        self._pairing_id = None
        # Flags that control MPIT handling based on ESXi versions
        self._skipMPITs = False
        self._alwaysMigrateMPITs = False

    def __enter__(self):
        """
        Context Manager internals
        """
        return self

    def __exit__(self, type, value, traceback):
        """
        Context Manager internals
        """
        pass

    def dr_url_for(self, path):
        """
        Helper function that generates URLs for calling DR REST Gateway APIs.
        """
        return "https://" + self._recoveryHms + path

    def get_dr_headers(self):
        """
        Helper function that sets up required headers for calling DR REST Gateway APIs.
        """
        if self._session_timestamp == 0:
            self.login_to_hms();
            self.login_to_remote_hms();
        headers = {
            "x-dr-session": self._session_id,
            "Content-Type": "application/json",
        }
        return headers

    def check_task(self, task_id):
        """
        Check a task through the REST gateway API.
        """
        logger.info(f"Checking task {task_id}")
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/tasks/{task_id}"),
                            headers=self.get_dr_headers(),
                            method="GET")
        result = execute_request_to_json(request)
        logger.info(f"Task {task_id} status is {result['status']}")
        return result["status"]

    def collect_environment(self, args):
        """
        Prompts the user for hostname and login credentials of the HMS appliances
        and their vCenters and stores them in the context for further use.
        """

        if "alwaysMigrateMPITs" in args and args.alwaysMigrateMPITs:
            self._alwaysMigrateMPITs = True

        if "primaryHms" in args and args.primaryHms is not None:
            self._primaryHms = args.primaryHms
        else:
            self._primaryHms = text_prompt("Enter primary HMS appliance hostname: ")

        if "recoveryHms" in args and args.recoveryHms is not None:
            self._recoveryHms = args.recoveryHms
        else:
            self._recoveryHms = text_prompt("Enter recovery HMS appliance hostname: ")

        if "primaryVCenterUser" in args and args.primaryVCenterUser is not None:
            self._primaryVCenterUser = args.primaryVCenterUser
        else:
            self._primaryVCenterUser = text_prompt("Enter primary vCenter username: ")

        if "primaryVCenterPass" in args and args.primaryVCenterPass is not None:
            self._primaryPassword = args.primaryVCenterPass
        else:
            self._primaryPassword = text_prompt("Enter primary vCenter password: ", mask=True)

        if self._primaryHms == self._recoveryHms:
            self._roboMode = True
            logger.info("Entering ROBO mode for replications within the same environment.")
            self._recoveryVCenterUser = self._primaryVCenterUser
            self._recoveryPassword = self._primaryPassword
            return

        if "recoveryVCenterUser" in args and args.recoveryVCenterUser is not None:
            self._recoveryVCenterUser = args.recoveryVCenterUser
        else:
            self._recoveryVCenterUser = text_prompt("Enter recovery vCenter username: ")

        if "recoveryVCenterPass" in args and args.recoveryVCenterPass is not None:
            self._recoveryPassword = args.recoveryVCenterPass
        else:
            self._recoveryPassword = text_prompt("Enter recovery vCenter password: ", mask=True)

    def login_to_hms(self):
        """
        Login to the HMS appliance, get a session token and add it to the environment.
        Other functions can then use it to call the remaining of the APIs.
        """
        logger.info("Logging to recovery VR REST API Gateway")
        auth = "Basic " + b64encode((self._recoveryVCenterUser + ":" + self._recoveryPassword).encode()).decode()
        request = Request(self.dr_url_for("/api/rest/vr/v2/session"),
                          headers={"Authorization" : auth},
                          method="POST")
        result = execute_request_to_json(request)
        self._session_id = result["session_id"]
        self._session_timestamp = int(time())

    def logout_from_hms(self):
        """
        Logout from the HMS appliance.
        """
        if self._session_id == None:
            return

        logger.info("Logging out from VR REST API Gateway")
        request = Request(self.dr_url_for("/api/rest/vr/v2/session"),
                          headers=self.get_dr_headers(),
                          method="DELETE")
        execute_request(request, expected_statuses=[200, 401])
        self._session_id = None
        self._session_timestamp = 0

    def login_to_remote_hms(self):
        """
        If a pairing is selected login to the remote HMS from the pairing.
        Otherwise do nothing.
        """
        if self._pairing_id == None:
            return
        if self._pairing["local_vc_server"]["name"] == self._pairing["remote_vc_server"]["name"]:
            # Remote login is not required with a ROBO setup.
            return
        pairing_id = self._pairing_id
        logger.info("Logging to remote HMS appliance")
        auth = "Basic " + b64encode((self._primaryVCenterUser + ":" + self._primaryPassword).encode()).decode()
        headers = self.get_dr_headers()
        headers["Authorization"] = auth
        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/remote-session"),
                          headers=headers,
                          method="POST")
        result = execute_request(request)

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

        pairings = sorted(pairings, key=lambda p: p["pairing_id"])
        choices = {}
        for pairing in pairings:
            local_vc = pairing["local_vc_server"]["name"]
            remote_vc = pairing["remote_vc_server"]["name"]

            if self._roboMode and (local_vc != remote_vc):
                continue
            if not self._roboMode and (local_vc == remote_vc):
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

    def collect_versions(self):
        """
        Connect to each vCenter if pyVmomi is available and gather the ESXi versions.
        Keep track if there are any ESXi older than 8.0.3u3 as that can affect the
        migration of replications using MPITs that have recently had a disk change.
        """
        if self._alwaysMigrateMPITs:
            logger.info("Skipping ESXi version checks as the user has requested to always migrate MPIT replications.")
            return

        if not CHECK_ESX_VERSIONS:
            logger.warning("Ignoring ESXi version checks, MPIT-enabled replications will not be migrated.")
            self._skipMPITs = True
            return

        def get_all_objects(content, vim_type):
            """
            Helper function to retrieve all object of a given
            kind in a vCenter environment
            """
            obj = {}
            container = content.viewManager.CreateContainerView(content.rootFolder, vim_type, True)
            for managed_object_ref in container.view:
                obj[managed_object_ref] = managed_object_ref.name
            container.Destroy()
            return obj

        def get_hosts_versions(content):
            """
            Helper function to collect the versions and patch level for
            all hosts in a vCenter environment
            """
            object_set = []
            for host in get_all_objects(content, [vim.HostSystem]):
                object_spec = vmodl.query.PropertyCollector.ObjectSpec()
                object_spec.obj = host
                object_set.append(object_spec)

            property_spec = vmodl.query.PropertyCollector.PropertySpec(all=False)
            property_spec.type = vim.HostSystem
            property_spec.pathSet = ["summary.config.product"]

            filter_spec = vmodl.query.PropertyCollector.FilterSpec()
            filter_spec.objectSet = object_set
            filter_spec.propSet = [property_spec]

            options = vmodl.query.PropertyCollector.RetrieveOptions()
            result = content.propertyCollector.RetrievePropertiesEx([filter_spec], options)
            hosts = {}
            for host in result.objects:
                hosts[host.obj] = {
                    "version" : host.propSet[0].val.version,
                    "patchLevel" : host.propSet[0].val.patchLevel,
                }
            return hosts

        def check_for_older_hosts(content):
            """
            Collects all hosts from the vSphere inventory and check
            that they are at the latest version in order to detect
            and warn about an issue with MPITs and recent disk changes
            """
            hosts = get_hosts_versions(content)
            for host in hosts:
                version = hosts[host]["version"].split('.')
                if (int(version[0]) < 8):
                    logger.warning(f"Found older host {hosts[host]}")
                    return True
                if (int(version[2]) < 3):
                    logger.warning(f"Found older host {hosts[host]}")
                    return True
                if not hosts[host]["patchLevel"].startswith("3"):
                    logger.warning(f"Found older host {hosts[host]}")
                    return True
            return False

        si = SmartConnect(host=self._pairing["local_vc_server"]["name"],
                              user=self._primaryVCenterUser,
                              pwd=self._primaryPassword,
                              sslContext=IGNORE_SSL_CONTEXT)
        if check_for_older_hosts(si.content):
            logger.warning("Older hosts found, replications using MPITs will not be migrated!")
            self._skipMPITs = True
        Disconnect(si)

        if self._roboMode:
            return

        si = SmartConnect(host=self._pairing["remote_vc_server"]["name"],
                              user=self._recoveryVCenterUser,
                              pwd=self._recoveryPassword,
                              sslContext=IGNORE_SSL_CONTEXT)
        if check_for_older_hosts(si.content):
            logger.warning("Older hosts found, replications using MPITs will not be migrated!")
            self._skipMPITs = True
        Disconnect(si)

    def get_replications(self):
        """
        Gets the available replications for the selected pairing.
        """
        replications = []
        pairing_id = self._pairing_id
        query = "extended_info=true&sort_by=name&order_by=asc&limit=200"
        url = self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications?{query}")
        while True:
            request = Request(url, headers=self.get_dr_headers(), method="GET")
            result = execute_request_to_json(request)
            replications += result["list"]
            next_batch = result["_meta"]["links"]["next"]
            if next_batch == None:
                break
            else:
                url = next_batch["href"]
        return replications

    def filter_replication(self, replication):
        """
        Check if a replication should be filtered out from the selection.
        """
        name = replication["name"]
        if "enhanced_replication" not in replication or replication["enhanced_replication"] == True:
            logger.warning(f"Ignoring replication {name} as it is already configured as enhanced replication.")
            return True
        unsupported = ["RECONFIGURING", "RECOVERED", "RECOVERING", "DISK_RESIZING", "MOVING", "UNKNOWN"]
        if replication["status"]["status"] in unsupported:
            replication_status = replication["status"]["status"]
            logger.warning(f"Ignoring replication {name} because of unsupported status {replication_status}.")
            return True
        return False

    def get_disks(self, replication_id):
        """
        Get the disks of the specified replication.
        """
        disks = []
        pairing_id = self._pairing_id
        url = self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/disks")
        while True:
            request = Request(url, headers=self.get_dr_headers(), method="GET")
            result = execute_request_to_json(request)
            disks += result["list"]
            next_batch = result["_meta"]["links"]["next"]
            if next_batch == None:
                break
            else:
                url = next_batch["href"]
        return disks

    def collect_extra_settings(self, replication):
        """
        Collects data about the replication that can be referred later
        by other workflow steps
        """
        replication["disks"] = self.get_disks(replication["id"])

    def reconfigure_replication(self, replication, enhanced_replication, preserve_mpit = True):
        """
        Reconfigure the specified replication for enhanced or legacy mode.
        Returns the reconfigure task id.
        """
        rep_display = replication['name'] + "/" + replication["id"]

        disks = replication["disks"]

        # Find the vm home disk. This is required to find a valid datastore
        # to set as the destination for any excluded disks
        for disk in disks:
            if disk["vm_disk"]["is_vm_home"]:
                vm_home = disk
                break

        payload_disks = []
        for disk in disks:
            payload = {
                "destination_disk_format": "SAME_AS_SOURCE",
                "destination_storage_policy_id": disk["destination_storage_policy_id"],
                "enabled_for_replication": disk["replicated"],
                "use_seeds": False,
                "vm_disk": disk["vm_disk"]
            }
            if disk["replicated"]:
                payload["destination_datastore_id"] = disk["destination_path"]["datastore_id"]
            else:
                payload["destination_datastore_id"] = vm_home["destination_path"]["datastore_id"]
            payload_disks.append(payload)

        pairing_id = self._pairing_id
        replication_id = replication["id"]
        body = json.dumps({
            "enhanced_replication": enhanced_replication,
            "rpo": replication["rpo"],
            "network_compression_enabled": replication["network_compression_enabled"],
            "mpit_enabled": replication["mpit_enabled"],
            "mpit_instances": replication["mpit_instances"],
            "mpit_days": replication["mpit_days"],
            "auto_replicate_new_disks": replication["auto_replicate_new_disks_enabled"],
            "lwd_encryption_enabled": replication["encryption_enabled"],
            "vm_data_sets_replication_enabled": replication["vm_data_sets_replication_enabled"],
            "quiesce_enabled": replication["quiescing_enabled"],
            "disks": payload_disks
        })

        logger.info(f"Reconfiguring replication {rep_display}")

        request = Request(self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}/actions/reconfigure"),
                          data=body.encode(),
                          headers=self.get_dr_headers(),
                          method="POST")
        result = execute_request_to_json(request)
        replication["last_reconfigure_task"] = result["id"]
        return result["id"]

    def check_replication(self, replication):
        """
        Report the replication status for the specified replication.
        """
        pairing_id = self._pairing_id
        replication_id = replication["id"]
        rep_display = replication['name'] + "/" + replication["id"]
        logger.info(f"Checking status for {rep_display}")
        url = self.dr_url_for(f"/api/rest/vr/v2/pairings/{pairing_id}/replications/{replication_id}")
        request = Request(url, headers=self.get_dr_headers(), method="GET")
        result = execute_request_to_json(request)
        logger.info(f"Status for replication {rep_display} is {result['status']['status']}")
        return result["status"]["status"] in ["OK"]

    def migration_generator(self, replication):
        """
        Encapsulates the migration flow for a single replication in a generator object
        that can be used to step though the flow from an external control
        """
        yield
        self.collect_extra_settings(replication)

        rep_display = replication['name'] + "/" + replication["id"]

        if self._skipMPITs and replication["mpit_enabled"]:
            logger.warning(f"Skipping replication {rep_display} as it uses MPITs.")
            return

        timer = int(time())
        replication["_tracking_started"] = int(time())
        while True:
            if (int(time()) - timer) > 10 * 60:
                logger.error(f"Replication {rep_display} could not start reconfiguration for 10 minutes.")
                return
            yield
            try:
                logger.info(f"Enabling enhanced mode for replication {rep_display}")
                task_id = self.reconfigure_replication(replication, True)
                timer = int(time())
                break
            except Exception as e:
                logger.error(f"Unexpected error while reconfiguring {rep_display} - {e}")
                continue

        while True:
            if (int(time()) - timer) > 10 * 60:
                logger.error(f"Replication {rep_display} did not finish reconfiguration for 10 minutes.")
                return
            yield
            try:
                task_status = self.check_task(task_id)
            except Exception as e:
                logger.error(f"Unexpected error when checking task {task_id} for {rep_display} - {e}")
                continue
            if task_status == "SUCCESS":
                timer = int(time())
                break
            if task_status == "ERROR":
                logger.error(f"Replication {rep_display} failed to reconfigure.")
                return

        while True:
            if (int(time()) - timer) > 10 * 60:
                logger.error(f"Replication {rep_display} did not settle into an OK state for 10 minutes.")
                self.reconfigure_replication(replication, False)
                return
            yield
            try:
                rep_ok = self.check_replication(replication)
            except Exception as e:
                logger.error(f"Unexpected error while checking replication {rep_display} - {e}")
                continue
            if rep_ok:
                return

    def migrate_replications(self):
        """
        Try to migrate legacy replications to enhanced mode.
        """
        # Collect replications for migration
        replications = [r for r in self.get_replications() if not self.filter_replication(r)]
        logger.info(f"Collected {len(replications)} replications")
        # Prepare the actual generators that will perform the migration tick by tick
        trackers = [self.migration_generator(r) for r in replications]
        batch_size = 40
        active = trackers[:batch_size]
        trackers = trackers[batch_size:]
        while len(active) > 0:
            for tracker in active:
                try:
                    tracker.__next__()
                except StopIteration:
                    active.remove(tracker)
                    if len(trackers) > 0:
                        active.append(trackers.pop())


def setup_arguments():
    """
    Perform argument parsing and return the result
    """
    parser = argparse.ArgumentParser()
    parser.add_argument('--primaryHms', type=str, help='Primary HMS appliance hostname')
    parser.add_argument('--recoveryHms', type=str, help='Recovery HMS appliance hostname')
    parser.add_argument('--primaryVCenterUser', type=str, help='Primary vCenter username')
    parser.add_argument('--primaryVCenterPass', type=str, help='Primary vCenter password')
    parser.add_argument('--recoveryVCenterUser', type=str, help='Recovery vCenter username')
    parser.add_argument('--recoveryVCenterPass', type=str, help='Recovery vCenter password')
    parser.add_argument('--alwaysMigrateMPITs', type=bool, action=argparse.BooleanOptionalAction,
                        help="Ignore version checks and migrate MPIT replications.")
    return parser.parse_args()

def main():
    args = setup_arguments()
    try:
        with Context() as ctx:
            ctx.collect_environment(args)
            if ctx.select_pairing():
                ctx.login_to_remote_hms() # Must be called after selecting a pairing
                ctx.collect_versions()
                ctx.migrate_replications()
            ctx.logout_from_hms()
    except (KeyboardInterrupt, SystemExit, EOFError):
        logger.warning("Migration workflow was interrupted!")
    else:
        logger.info("Migration workflow completed successfully.")

if __name__ == "__main__":
    main()
