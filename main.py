#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address
MODBUS protocol.

Usage: ./main.py

License:
    MIT License

    Copyright (c) 2024-2025 Wishnu Adhi Pahlevi <wishnu@pahlevi.id>

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the “Software”), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in
    all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.

The main application file.
"""
# Import system dependencies.
import sys
from signal import signal as os_signal, SIGTERM, SIGINT, SIGHUP
from time import sleep
from glob import glob
from sdnotify import SystemdNotifier
import yaml

# Import custom build dependencies.
from arkanod.evc.const import (MODBUS_TYPE_LIST,
                               REGISTER_TYPE_LIST,
                               SWAP_TYPE_LIST,
                               DATA_TYPE_LIST,
                               ARCHIVE_LOG_LIST,
                               ARCHIVE_LOG_ENABLED)
from arkanod.evc.device_read import DeviceRead
from arkanod.evc.db_tables_create import init_create_tables
from danismod.yaml_include import Loader
from danismod.funcs import print_log, app_exit
from danismod.db_funcs import db_config_check

# Add the constructor to be used in yaml.load() function.
Loader.add_constructor('!include', Loader.include)

# Variable initialization for storing configured group_ids.
group_id_list = {}

# Initialization of predefined constants and operation variables when --create-tables is called.
if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
    # from arkanod.evc.db_const import TRIGGER_REQ_DATALOG, EVENT_NOT_UPDATE_CHECK
    register_conversion_fields = {archive_log: [] for archive_log in ARCHIVE_LOG_LIST}

def signal_term_handler(threads: list):
    """
    Basic OS signal handler to control the runtime.

    Mandatory keyword argument:
    threads: list; The list of active threads.
    """
    def handler(signal, frame):
        frame = None if isinstance(frame, object) else None
        for thread in threads:
            if thread.is_alive():
                thread.shutdown()
        if signal in [SIGTERM, SIGINT]:
            app_exit()
        elif signal == SIGHUP:
            # Ensure all threads are shut down gracefully.
            while True:
                live_threads = 0
                for thread in threads:
                    if thread.is_alive():
                        live_threads += 1

                if live_threads == 0:
                    # Start the main() again.
                    main()
                    return

    return handler

def register_group_paramcheck(param_name: str, grp_item_index: int, register_group_item: dict,
                              mb_config_check_item: dict, item_index: int) -> int:
    """
    Sanity check a parameter in a particular register_group member.
    It also checks whether this register_group member is configured in any of the configured
    EVC logs.

    Mandatory keyword arguments:
    param_name: str; The register_group parameter name.
    grp_item_index: int; Index number from the list of register_group members.
    """
    log_types = ARCHIVE_LOG_LIST[:]
    log_types.append('current_log')
    error_len = 0

    if param_name in register_group_item:
        if param_name == 'group_id':
            exists_count = 0

            # The loop checks whether this register_group member exists in the configured EVC logs.
            for current_log_type in log_types:
                if register_group_item[param_name] in mb_config_check_item[current_log_type]['group_ids']:
                    exists_count = exists_count + 1

            # Throw an error if this register_group member does not exist in any of the configured
            # EVC logs.
            if exists_count == 0:
                print_log(f"[Item {item_index} - register_group - Group Item {grp_item_index}] "
                          f"Unable to find {param_name} in any log type group_ids.", 'error')
                error_len += 1

        if param_name != 'type' and isinstance(register_group_item[param_name], int) is False:
            print_log(f"[Item {item_index} - register_group - Group Item {grp_item_index}] Invalid"
                      f" {param_name} configuration. It should be an integer.", 'error')
            error_len += 1
        elif param_name == 'type' and register_group_item[param_name] not in REGISTER_TYPE_LIST:
            print_log(f"[Item {item_index} - register_group - Group Item {grp_item_index}] Invalid"
                      f" Modbus register type option (type: {register_group_item[param_name]}). "
                      f"Supported options are: {MODBUS_TYPE_LIST}.", 'error')
            error_len += 1
    else:
        print_log(f"[Item {item_index} - register_group - Group Item {grp_item_index}] Unable to "
                  "find {param_name} configuration.", 'error')
        error_len += 1

    return error_len

def register_conversion_paramcheck(param_name: str,
                                   conversion_item_index: int,
                                   mb_config_check_item: dict,
                                   register_conversion_item: dict,
                                   mb_config_detail: dict, item_index: int) -> int:
    """
    Sanity check a parameter in a particular register_conversion member.
    It also checks whether this register_conversion member is configured in any of the configured
    register_groups.

    Mandatory keyword arguments:
    param_name: str; The register_conversion parameter name.
    conversion_item_index: int; Index number from the list of register_conversion members.
    """
    error_len = 0

    # Sanity check for name, group_id, registers, data_type, swap, precision configuration.
    if param_name in register_conversion_item:
        if param_name == 'group_ids':

            # The loop checks whether this register_conversion member exists in the configured
            # register_groups.
            for curr_group_id in register_conversion_item['group_ids']:
                exists_count = 0
                for current_register_group in mb_config_check_item['register_group']:
                    if curr_group_id == current_register_group['group_id']:
                        exists_count = 1
                        break

                # Throw an error if this register_conversion member does not exist in any of the
                # configured register_groups.
                if exists_count == 0:
                    print_log(f"[Item {item_index} - register_conversion - Conversion Item "
                              f"{conversion_item_index}] Unable to find group_ids: {curr_group_id}"
                              " in any register_group.", 'error')
                    error_len += 1

        elif param_name == 'registers':
            if isinstance(register_conversion_item['registers'], list) is False:
                print_log(f"[Item {item_index} - register_conversion - Group Item "
                          f"{conversion_item_index}] Invalid `registers` configuration for "
                          f"conversion name: {register_conversion_item['name']}. It should be a "
                          "list [start_reg_addr, end_reg_addr].", 'error')
                error_len += 1
            elif register_conversion_item['registers'][0] > register_conversion_item['registers'][1]:
                print_log(f"[Item {item_index} - register_conversion - Group Item "
                          f"{conversion_item_index}] Invalid `registers` configuration for "
                          f"conversion name: {register_conversion_item['name']}. The "
                          "start_reg_addr should be less than end_reg_addr.", 'error')
                error_len += 1
            else:
                for curr_group_id in register_conversion_item['group_ids']:
                    for current_register_group in mb_config_check_item['register_group']:
                        if curr_group_id == current_register_group['group_id']:
                            regnum = {
                                'start': current_register_group['address'],
                                'end': current_register_group['address'] + current_register_group['count'] - 1
                            }

                            if not regnum['start'] <= register_conversion_item['registers'][0] <= regnum['end'] or not regnum['start'] <= register_conversion_item['registers'][1] <= regnum['end']:
                                print_log(f"[Item {item_index} - register_conversion - Group Item "
                                          f"{conversion_item_index}] Invalid `registers` "
                                          "configuration for conversion name: "
                                          f"{register_conversion_item['name']}. Modbus register "
                                          "address not in the correct range of group_id "
                                          f"{curr_group_id} (should be between "
                                          f"{regnum['start']} - {regnum['end']}).", 'error')
                                error_len += 1
        elif param_name == 'data_type' and register_conversion_item['data_type'] not in DATA_TYPE_LIST:
            print_log(f"[Item {item_index} - register_conversion - Group Item "
                      f"{conversion_item_index}] Invalid `data_type` configuration for conversion "
                      f"name: {register_conversion_item['name']}. Valid options are: "
                      f"{DATA_TYPE_LIST}.", 'error')
            error_len += 1
        elif param_name == 'swap' and register_conversion_item['swap'] not in SWAP_TYPE_LIST:
            print_log(f"[Item {item_index} - register_conversion - Group Item "
                      f"{conversion_item_index}] Invalid `swap` configuration for conversion name:"
                      f" {register_conversion_item['name']}. Valid options are: {SWAP_TYPE_LIST}.",
                      'error')
            error_len += 1
        elif param_name == 'precision':
            if (isinstance(register_conversion_item['precision'], int) is False and
                (register_conversion_item['precision'] != 'none' or
                 register_conversion_item['precision'] < 0)):
                print_log(f"[Item {item_index} - register_conversion - Group Item "
                          f"{conversion_item_index}] Invalid `precision` configuration for "
                          f"conversion name: {register_conversion_item['name']}. Minimum valid "
                          "value is 0 or none.", 'error')
                error_len += 1
    else:
        if param_name == 'precision':
            print_log(f"[Item {item_index} - register_conversion - Conversion Item "
                      f"{conversion_item_index}] Unable to find `precision` configuration for "
                      f"conversion name {register_conversion_item['name']}. Defaulting to none.",
                      'debug')
            mb_config_detail[item_index]['register_conversion'][conversion_item_index]['precision'] = 'none'
        else:
            print_log(f"[Item {item_index} - register_conversion - Conversion Item "
                      f"{conversion_item_index}] Unable to find {param_name} configuration.",
                      'error')
            error_len += 1

    return error_len

def main():
    """
    It's the MainThread process!
    All MODBUS device threads will be started from here.
    """
    mb_config_detail = []
    mb_config_files = []
    error_len = 0

    # Looking for all *.modbus.yaml files in <base_dir>/config/slaves/ directory, representing EVC
    # devices' MODBUS configuration.
    for slave_config in glob('config/slaves/*.modbus.yaml'):
        with open(slave_config, 'r', encoding='utf-8') as mb_config:
            mb_config_files.append(slave_config)
            print_log(f"Loading Modbus device configurations from {slave_config}...")
            mb_config_detail += yaml.load(mb_config, Loader)

    mb_config_check_all = mb_config_detail

    if 'mb_config_check_all' in vars():
        # START - Modbus config sanity check and default value.

        error_len = 0
        evctime_reg = {}
        for item_index, mb_config_check_item in enumerate(mb_config_check_all):

            # START - Sanity check for type, port and host configuration.

            if 'type' in mb_config_check_item:
                if mb_config_check_item['type'] == 'rtu':
                    if 'port' not in mb_config_check_item:
                        print_log(f"[{mb_config_files[item_index]}] No Modbus RTU device port "
                                  "defined.", 'error')
                        error_len += 1
                elif mb_config_check_item['type'] == 'rtuovertcp':
                    if 'port' not in mb_config_check_item or 'host' not in mb_config_check_item:
                        print_log(f"[{mb_config_files[item_index]}] No Modbus RTU device host "
                                  "and/or port defined.", 'error')
                        error_len += 1
                    elif isinstance(mb_config_check_item['port'], int) is False:
                        print_log(f"[{mb_config_files[item_index]}] Invalid TCP port setting for "
                                  "Modbus RTU device.", 'error')
                        error_len += 1
                elif mb_config_check_item['type'] == 'tcp':
                    if 'port' not in mb_config_check_item or 'host' not in mb_config_check_item:
                        print_log(f"[{mb_config_files[item_index]}] No Modbus TCP device host "
                                  "and/or port defined.", 'error')
                        error_len += 1
                elif mb_config_check_item['type'] == 'ascii':
                    if 'port' not in mb_config_check_item:
                        print_log(f"[{mb_config_files[item_index]}] No Modbus ASCII device port "
                                  "defined.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]}] Invalid Modbus device type (type: )"
                              " defined.", 'error')
                    error_len += 1
            else:
                print_log(f"[{mb_config_files[item_index]}] No Modbus device type defined.")
                if 'port' in mb_config_check_item:
                    if 'host' in mb_config_check_item:
                        print_log(f"[{mb_config_files[item_index]}] Assuming Modbus device type of "
                                  "RTU over TCP (type: rtuovertcp) on "
                                  f"{mb_config_check_item['host']} port "
                                  f"{mb_config_check_item['port']}.")
                        mb_config_detail[item_index]['type'] = 'rtu'
                    else:
                        print_log(f"[{mb_config_files[item_index]}] Assuming Modbus device type of "
                                  f"RTU (type: rtu) on port {mb_config_check_item['port']}.")
                        mb_config_detail[item_index]['type'] = 'rtu'
                else:
                    print_log(f"[{mb_config_files[item_index]}] Cannot assume Modbus device type.",
                              'error')
                    error_len += 1

            # END - Sanity check for type, port and host configuration.

            # START - Sanity check for name configuration.

            if 'name' not in mb_config_check_item:
                print_log(f"[{mb_config_files[item_index]}] Modbus device name (name: unique) must "
                          "be specified.", 'error')
                error_len += 1
            elif mb_config_check_item['name'] == "":
                print_log(f"[{mb_config_files[item_index]}] Modbus device name (name: unique) "
                          "cannot be blank.", 'error')
                error_len += 1

            # END - Sanity check for name configuration.

            # START - Sanity check for timeout_seconds configuration.

            if 'timeout_seconds' in mb_config_check_item:
                if isinstance(mb_config_check_item['timeout_seconds'], int):
                    if (mb_config_check_item['timeout_seconds'] < 1 or
                        mb_config_check_item['timeout_seconds'] > 300):
                        print_log(f"[{mb_config_files[item_index]}] Invalid Modbus device "
                                  "connection timeout (timeout_seconds: ). Valid setting is between"
                                  " 1 and 300 seconds.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]}] Invalid Modbus device connection "
                              "timeout (timeout_seconds: ). Valid setting is between 1 and 300 "
                              "seconds.", 'error')
                    error_len += 1
            else:
                print_log(f"[{mb_config_files[item_index]}] Undefined Modbus device connection "
                          "timeout (timeout_seconds: ). Using default setting (3 seconds).",
                          'debug')
                mb_config_detail[item_index]['timeout_seconds'] = 3

            # END - Sanity check for timeout_seconds configuration.

            # START - Sanity check for wait_milliseconds configuration.

            if 'wait_milliseconds' in mb_config_check_item:
                if isinstance(mb_config_check_item['wait_milliseconds'], int):
                    if mb_config_check_item['wait_milliseconds'] < 10 or mb_config_check_item['wait_milliseconds'] > 10000:
                        print_log(f"[{mb_config_files[item_index]}] Invalid Modbus polling wait "
                                  "interval (wait_milliseconds: ). Valid setting is between 10 and"
                                  " 10000 milliseconds.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]}] Invalid Modbus polling wait "
                              "interval (wait_milliseconds: ). Valid setting is between 10 and "
                              "10000 milliseconds.", 'error')
                    error_len += 1
            else:
                print_log(f"[{mb_config_files[item_index]}] Undefined Modbus polling wait interval "
                          "(wait_milliseconds: ). Using default setting (100 milliseconds).",
                          'debug')
                mb_config_detail[item_index]['wait_milliseconds'] = 100

            # END - Sanity check for wait_milliseconds configuration.

            # START - Sanity check for current_log configuration.

            if 'current_log' in mb_config_check_item:

                # START - Sanity check for current_log --> scan_interval_ms configuration.

                if 'scan_interval_ms' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['scan_interval_ms'], int):
                        if mb_config_check_item['current_log']['scan_interval_ms'] < 1000:
                            print_log(f"[{mb_config_files[item_index]} - current_log] Invalid "
                                      "polling interval configuration (scan_interval_ms: ). Valid "
                                      "minimum setting is 1000 milliseconds.", 'error')
                            error_len += 1
                    else:
                        print_log(f"[{mb_config_files[item_index]} - current_log] Invalid polling "
                                  "interval configuration (scan_interval_ms: ). Valid minimum "
                                  "setting is 1000 milliseconds.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]} - current_log] Unable to find "
                              "polling interval configuration (scan_interval_ms: ).", 'error')
                    error_len += 1

                # END - Sanity check for current_log --> scan_interval_ms configuration.

                # START - Sanity check for current_log --> evc_time_regname configuration.

                if 'evc_time_regname' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['evc_time_regname'], str) is False:
                        print_log(f"[{mb_config_files[item_index]} - current_log] Invalid "
                                  "evc_time_regname configuration (evc_time_regname: ).", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]} - current_log] Unable to find "
                              "evc_time_regname configuration (evc_time_regname: ).", 'error')
                    error_len += 1

                # END - Sanity check for current_log --> evc_time_regname configuration.

                # START - Sanity check for current_log --> debug configuration.

                if 'debug' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['debug'], bool) is False:
                        print_log(f"[{mb_config_files[item_index]} - current_log] Invalid debug "
                                  "configuration (debug: ). Valid configuration are boolean: True"
                                  " or False.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]} - current_log] No debug "
                              "configuration found. Assuming debug: False.", 'debug')
                    mb_config_detail[item_index]['current_log']['debug'] = False

                # END - Sanity check for current_log --> debug configuration.

                # START - Sanity check for current_log --> group_ids configuration.

                if 'group_ids' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['group_ids'], list) is False:
                        print_log(f"[{mb_config_files[item_index]} - current_log] Invalid group_ids"
                                  " configuration (group_ids: ). It should be a list.", 'error')
                        error_len += 1
                else:
                    print_log(f"[{mb_config_files[item_index]} - current_log] No group_ids "
                              "configuration found.", 'error')
                    error_len += 1

                # END - Sanity check for current_log --> group_ids configuration.

                # Create Group ID list for current_log if --create-tables is called.
                if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
                    group_id_list['current_log'] = mb_config_check_item['current_log']['group_ids']
                    register_conversion_fields.update({'current_log': []})

            else:
                print_log(f"[{mb_config_files[item_index]}] Unable to find current_log "
                          "configuration.", 'error')
                error_len += 1

            # END - Sanity check for current_log configuration.

            # START - Sanity check for hourly_log, daily_log, monthly_log configuration.
            for current_archive_log in ARCHIVE_LOG_LIST:
                if current_archive_log in mb_config_check_item:

                    # START - Sanity check for hourly_log, daily_log, monthly_log -->
                    # max_retention configuration.

                    if 'max_retention' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['max_retention'], int):
                            if mb_config_check_item[current_archive_log]['max_retention'] < 1:
                                print_log(f"[{mb_config_files[item_index]} - {current_archive_log}]"
                                          " The minimum value of max_retention is 1. Disabling it.",
                                          'debug')
                                mb_config_detail[item_index][current_archive_log]['max_retention'] = 0
                        else:
                            print_log(f"[{mb_config_files[item_index]} - {current_archive_log}]"
                                      " Invalid max_retention configuration (max_retention: ) "
                                      "found. The minimum valid value should be 1.", 'error')
                            error_len += 1
                    else:
                        mb_config_detail[item_index][current_archive_log]['max_retention'] = 0

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> max_retention
                    # configuration.

                    # START - Sanity check for hourly_log, daily_log, monthly_log --> debug
                    # configuration.

                    if 'debug' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['debug'], bool) is False:
                            print_log(f"[{mb_config_files[item_index]} - {current_archive_log}] "
                                      "Invalid debug configuration (debug: ). The valid value are "
                                      "boolean: true or false.", 'error')
                            error_len += 1
                    else:
                        print_log(f"[{mb_config_files[item_index]} - {current_archive_log}] No "
                                  "debug configuration found. Assuming debug: False.", 'debug')
                        mb_config_detail[item_index][current_archive_log]['debug'] = False

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> debug
                    # configuration.

                    # START - Sanity check for hourly_log, daily_log, monthly_log --> group_ids
                    # configuration.

                    if 'group_ids' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['group_ids'], list) is False:
                            print_log(f"[{mb_config_files[item_index]} - {current_archive_log}] "
                                      "Invalid group_ids configuration (group_ids: ). It should be "
                                      "a list.", 'error')
                            error_len += 1
                    else:
                        print_log(f"[{mb_config_files[item_index]} - current_log] No group_ids "
                                  "configuration found.", 'error')
                        error_len += 1

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> group_ids
                    # configuration.

                    # Create group_id list for hourly_log, daily_log, monthly_log.
                    group_id_list[current_archive_log] = mb_config_check_item[current_archive_log]['group_ids']

                else:
                    print_log(f"[{mb_config_files[item_index]}] Unable to find "
                              f"{current_archive_log} configuration. Disabling it.")
                    ARCHIVE_LOG_ENABLED[current_archive_log] = False

            # END - Sanity check for hourly_log, daily_log, monthly_log configuration.

            # START - Sanity check for register_group configuration.

            if 'register_group' in mb_config_check_item:
                if isinstance(mb_config_check_item['register_group'], list) is True:
                    for grp_item_index, register_group_item in enumerate(mb_config_check_item['register_group']):
                        # START - Sanity check for group_id, slave, address, count, type c
                        # onfiguration.
                        for param_name in ['group_id',
                                                'slave',
                                                'address',
                                                'count',
                                                'type']:
                            error_len += register_group_paramcheck(
                                param_name = param_name,
                                grp_item_index = grp_item_index,
                                register_group_item=register_group_item,
                                mb_config_check_item=mb_config_check_item,
                                item_index=item_index)
                        # END - Sanity check for group_id, slave, address, count, type
                        # configuration.
                else:
                    print_log(f"[{mb_config_files[item_index]}] Invalid register_group "
                              "configuration (register_group: ). It should be a list.",
                              'error')
                    error_len += 1
            else:
                print_log(f"[{mb_config_files[item_index]}] Unable to find register_group "
                          "configuration.", 'error')
                error_len += 1

            # END - Sanity check for register_conversion configuration.

            # START - Sanity check for register_conversion configuration.

            if 'register_conversion' in mb_config_check_item:

                if isinstance(mb_config_check_item['register_conversion'], list) is True:
                    for grp_item_index, register_conversion_item in enumerate(mb_config_check_item['register_conversion']):
                        # START - Sanity check for name, group_ids, registers, data_type, swap,
                        # precision configuration.

                        for param_name in ['name',
                                            'group_ids',
                                            'registers',
                                            'data_type',
                                            'swap',
                                            'precision']:
                            error_len += register_conversion_paramcheck(
                                param_name=param_name,
                                conversion_item_index=grp_item_index,
                                mb_config_check_item=mb_config_check_item,
                                register_conversion_item=register_conversion_item,
                                mb_config_detail=mb_config_detail,
                                item_index=item_index)

                        if error_len == 0 and register_conversion_item['name'] == mb_config_check_item['current_log']['evc_time_regname']:
                            evctime_reg[mb_config_check_item['name']] = {
                                'name': register_conversion_item['name'],
                                'data_type': register_conversion_item['data_type']
                            }

                        # END - Sanity check for name, group_ids, registers, data_type, swap,
                        # precision configuration.

                        # List items for current_log and archive log table creation.
                        if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
                            for group_id in register_conversion_item['group_ids']:
                                if group_id in group_id_list['current_log']:
                                    register_conversion_fields['current_log'].append({
                                        'item': register_conversion_item['name'],
                                        'data_type': register_conversion_item['data_type']})
                                elif group_id in group_id_list['hourly_log']:
                                    register_conversion_fields['hourly_log'].append({
                                        'item': register_conversion_item['name'],
                                        'data_type': register_conversion_item['data_type']})
                                elif group_id in group_id_list['daily_log']:
                                    register_conversion_fields['daily_log'].append({
                                        'item': register_conversion_item['name'],
                                        'data_type': register_conversion_item['data_type']})
                                elif group_id in group_id_list['monthly_log']:
                                    register_conversion_fields['monthly_log'].append({
                                        'item': register_conversion_item['name'],
                                        'data_type': register_conversion_item['data_type']})
                else:
                    print_log(f"[{mb_config_files[item_index]}] Invalid register_conversion "
                              "configuration (register_conversion: ). It should be a list.",
                              'error')
                    error_len += 1
            else:
                print_log(f"[{mb_config_files[item_index]}] Unable to find register_conversion "
                          "configuration.", 'error')
                error_len += 1

            # END - Sanity check for register_conversion configuration.
    else:
        print_log('No Modbus configuration found.', 'error')
        error_len += 1

    # Check error_len only when --config-test argument is not passed.
    if not (len(sys.argv) > 1 and sys.argv[1] == '--config-test') or len(sys.argv) == 1:
        if error_len > 0:
            app_exit(1)
        elif len(mb_config_files) == 0:
            print_log("No Modbus device configuration file found, aborting.")
            app_exit(1)
        else:
            print_log('Modbus device configuration(s) loaded successfully.')

    # END - Modbus config sanity check and default value.

    # DB config sanity check, tables existence and default value.
    db_params = db_config_check()

    if db_params is False:
        app_exit(1)

    if len(sys.argv) > 1:
        if sys.argv[1] == '--create-tables':
            # Create tables if --create-tables argument is passed.
            init_create_tables(db_params[0], register_conversion_fields, mb_config_check_all[0])
            return

        if sys.argv[1] == '--config-test':
            # Check configuration only if --config-test argument is passed.
            print()
            print_log(f"Configuration test is {('successful' if error_len == 0 else 'failed')}.")
            return

    # MODBUS device threads start here.
    threads = []

    # Register some OS signals received to be processed by the configured handler.
    for current_os_signal in [SIGINT, SIGHUP, SIGTERM]:
        os_signal(current_os_signal, signal_term_handler(threads=threads))

    # MODBUS poll each EVC device ID
    for mb_config_item in mb_config_detail:
        thread = DeviceRead(mb_config_item, evctime_reg[mb_config_item['name']], db_params[0])
        thread.name = mb_config_item['name']
        threads.append(thread)
        thread.start()

    # Delete unnecesary variables to free some memory space
    del mb_config_detail, db_params, mb_config_check_all

    # Notify systemd that the startup routines are done.
    SystemdNotifier().notify("READY=1")

    while True:
        live_threads = 0
        for thread in threads:
            if thread.is_alive():
                live_threads += 1
                thread.join()

        if live_threads == 0:
            return

        sleep(0.1)

if __name__ == '__main__':
    main()
