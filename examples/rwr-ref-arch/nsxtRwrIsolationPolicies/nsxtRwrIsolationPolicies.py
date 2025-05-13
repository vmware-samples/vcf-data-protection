#!/usr/bin/env python
# requires python 3

# Copyright (c) 2023-2024 Broadcom. All Rights Reserved.
# Broadcom Confidential. The term "Broadcom" refers to Broadcom Inc.
# and/or its subsidiaries.

from constants import *

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
from nsxServiceClient import NsxtServiceClient

def setup_logger(log_filename: str, log_level: int):
    # if log_level == logging.DEBUG:
    #     formatter_str = '%(asctime)s - %(filename)s:%(lineno)d - %(levelname)s - %(message)s'
    # else:
    #     formatter_str = '%(asctime)s - %(levelname)s - %(message)s'
    formatter_str = '%(asctime)s - %(levelname)s - %(message)s'

    result_logger = logging.getLogger()
    result_logger.setLevel(log_level)
    file_handler = logging.FileHandler(filename=log_filename, encoding='utf-8')
    file_handler.setFormatter(logging.Formatter(formatter_str))
    result_logger.addHandler(file_handler)

    # Adding console handler with same format as the log file
    ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)
    ch.setFormatter(logging.Formatter(formatter_str))
    result_logger.addHandler(ch)
    return result_logger

def pars_cli_args():
    parser = argparse.ArgumentParser(
        description="",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument("--nsxManager",
                        help=" ",
                        required=True)
    parser.add_argument("-u", "--user",
                        help=" ",
                        required=True)
    parser.add_argument("-p", "--password",
                        help=" ",
                        required=True)

    parser.add_argument("--cmd",
                        help=" ",
                        required=True,
                        choices=[
                            'createRwrPolicies',
                            'deleteRwrPolicies',
                            'assignRwrIsolationPolicy',
                            'removeRwrIsolationPolicy']
                        )

    parser.add_argument("--tier1_name",
                        help=" ",
                        required=False)

    parser.add_argument("--vm_uuid",
                        help=" ",
                        required=False)

    parser.add_argument("--policy",
                        help=" ",
                        required=False,
                        choices=[policy.name for policy in NetworkIsolationLevel])

    parser.add_argument("-v", "--verbose",
                        help=" ",
                        action='store_true')
    return parser.parse_args()


def main():
    logger = setup_logger(log_filename="output.log", log_level=logging.INFO)
    logger.info("\n------------------------ Starting NSX RWR Isolation Policies CLI tool -----------------------\n")

    args = pars_cli_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    nsx_service = NsxtServiceClient(
        hostname=args.nsxManager,
        user=args.user,
        password=args.password,
        logger=logger)

    if args.cmd == "createRwrPolicies":
        logger.info("\n------------------------       Running Create RWR Policies CMD        -----------------------\n")
        nsx_service.create_isolation_policies(str(args.tier1_name))
    if args.cmd == "deleteRwrPolicies":
        logger.info("\n------------------------       Running Delete RWR Policies CMD        -----------------------\n")
        nsx_service.delete_isolation_policies(str(args.tier1_name))
    if args.cmd == "assignRwrIsolationPolicy":
        logger.info("\n------------------------    Running assign VM isolation policy CMD    -----------------------\n")
        nsx_service.assign_rwr_isolation_policy_to_vms(
            [args.vm_uuid], NetworkIsolationLevel[args.policy])
    if args.cmd == "removeRwrIsolationPolicy":
        logger.info("\n------------------------    Running remove VM isolation policy CMD    -----------------------\n")
        nsx_service.remove_rwr_isolation_policy_from_vms([args.vm_uuid], NetworkIsolationLevel[args.policy])

    # TODO:
    #  1. Implement a method for a given segment to to find out its context including:
    #     tier-1, tier-0, domain, topology org-id, and policy enforcement point to work with.
    #  2. CLI args parsing:
    #     - Proper commands help info and context based args parsing

if __name__ == '__main__':
    main()
