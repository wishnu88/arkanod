#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address MODBUS protocol.

Usage: python3 -m arkanod

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

# Import custom build dependencies.
from arkanod.evc.const import *
from arkanod.evc.device_read import *
from danismod.yaml_include import *
from danismod.funcs import printLog
from danismod.db_funcs import db_config_check

# Variable initialization for storing configured group_ids.
group_id_list = {}

# Initialization of predefined constants and operation variables when --create-tables is called.
if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
    from arkanod.evc.db_const import TRIGGER_REQ_DATALOG, EVENT_NOT_UPDATE_CHECK
    register_conversion_fields = {archive_log: [] for archive_log in ARCHIVE_LOG_LIST}

def app_exit(exit_val: int = 0):
    """
    Exit the main program with 0 exit status by default.

    Optional keyword argument:
    exit_val: int; default to 0, means no error occurred while exiting, error indicated if it is greater than 0 (see UNIX exit status).
    """
    try:
        printLog('Main thread exiting with error(s)...' if exit_val > 0 else 'Main thread is exiting...')   
        sys.exit(exit_val)
    except Exception as e:
        printLog('Error(s) occurred in main thread, right before exit: %s' % e, 'error')


def signal_term_handler(threads: list):
    """
    Basic OS signal handler to control the runtime.

    Mandatory keyword argument:
    threads: list; The list of active threads.
    """
    def handler(signal, frame):
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

def register_group_paramcheck(param_name: str, grp_item_index: int, register_group_item: dict, mb_config_check_item: dict, item_index: int):
    """
    Sanity check a parameter in a particular register_group member.
    It also checks whether this register_group member is configured in any of the configured EVC logs.

    Mandatory keyword arguments:
    param_name: str; The register_group parameter name.
    grp_item_index: int; Index number from the list of register_group members.
    """
    global error_len

    log_types = ARCHIVE_LOG_LIST[:]
    log_types.append('current_log')

    if param_name in register_group_item:
        if param_name == 'group_id':
            exists_count = 0

            # The loop checks whether this register_group member exists in the configured EVC logs.
            for current_log_type in log_types:
                if register_group_item[param_name] in mb_config_check_item[current_log_type]['group_ids']:
                    exists_count = exists_count + 1
            
            # Throw an error if this register_group member does not exist in any of the configured EVC logs.
            if exists_count == 0:
                printLog('[Item %s - register_group - Group Item %s] Unable to find %s in any log type group_ids.' % (item_index, grp_item_index, param_name), 'error')
                error_len = error_len + 1
        
        if param_name != 'type' and isinstance(register_group_item[param_name], int) == False:
            printLog('[Item %s - register_group - Group Item %s] Invalid %s configuration. It should be an integer.' % (item_index, grp_item_index, param_name), 'error')
            error_len = error_len + 1
        elif param_name == 'type' and register_group_item[param_name] not in REGISTER_TYPE_LIST:
            printLog('[Item %s - register_group - Group Item %s] Invalid Modbus register type option (type: %s). Supported options are: %s.' % (item_index, grp_item_index, register_group_item[param_name], MODBUS_TYPE_LIST), 'error')
            error_len = error_len + 1
    else:
        printLog('[Item %s - register_group - Group Item %s] Unable to find %s configuration.' % (item_index, grp_item_index, param_name), 'error')
        error_len = error_len + 1

def register_conversion_paramcheck(param_name: str, conversion_item_index: int, mb_config_check_item: dict, register_conversion_item: dict, mb_config_detail: dict, item_index: int):
    """
    Sanity check a parameter in a particular register_conversion member.
    It also checks whether this register_conversion member is configured in any of the configured register_groups.

    Mandatory keyword arguments:
    param_name: str; The register_conversion parameter name.
    conversion_item_index: int; Index number from the list of register_conversion members.
    """
    global error_len

    # Sanity check for name, group_id, registers, data_type, swap, precision configuration.
    if param_name in register_conversion_item:
        if param_name == 'group_ids':

            # The loop checks whether this register_conversion member exists in the configured register_groups.
            for curr_group_id in register_conversion_item['group_ids']:
                exists_count = 0
                for current_register_group in mb_config_check_item['register_group']:
                    if curr_group_id == current_register_group['group_id']:
                        exists_count = 1
                        break

                # Throw an error if this register_conversion member does not exist in any of the configured register_groups.
                if exists_count == 0:
                    printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find group_ids: %s in any register_group.' % (item_index, conversion_item_index, curr_group_id), 'error')
                    error_len = error_len + 1

        elif param_name == 'registers':
            if isinstance(register_conversion_item['registers'], list) == False:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. It should be a list [start_reg_addr, end_reg_addr].' % (item_index, conversion_item_index, 'registers', register_conversion_item['name']), 'error')
                error_len = error_len + 1
            elif register_conversion_item['registers'][0] > register_conversion_item['registers'][1]:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. The start_reg_addr should be less than end_reg_addr.' % (item_index, conversion_item_index, 'registers', register_conversion_item['name']), 'error')
                error_len = error_len + 1
            else:
                for curr_group_id in register_conversion_item['group_ids']:
                    for current_register_group in mb_config_check_item['register_group']:
                        if curr_group_id == current_register_group['group_id']:
                            regnum = {
                                'start': current_register_group['address'],
                                'end': current_register_group['address'] + current_register_group['count'] - 1
                            }

                            if not regnum['start'] <= register_conversion_item['registers'][0] <= regnum['end'] or not regnum['start'] <= register_conversion_item['registers'][1] <= regnum['end']:
                                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. Modbus register address not in the correct range of group_id %s (should be between %s - %s).' % (item_index, conversion_item_index, 'registers', register_conversion_item['name'], curr_group_id, regnum['start'], regnum['end']), 'error')
                                error_len = error_len + 1
        elif param_name == 'data_type' and register_conversion_item['data_type'] not in DATA_TYPE_LIST:
            printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. Valid options are: %s.' % (item_index, conversion_item_index, 'data_type', register_conversion_item['name'], DATA_TYPE_LIST), 'error')
            error_len = error_len + 1
        elif param_name == 'swap' and register_conversion_item['swap'] not in SWAP_TYPE_LIST:
            printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. Valid options are: %s.' % (item_index, conversion_item_index, 'swap', register_conversion_item['name'], SWAP_TYPE_LIST), 'error')
            error_len = error_len + 1
        elif param_name == 'precision':
            if isinstance(register_conversion_item['precision'], int) == False and register_conversion_item['precision'] != 'none':
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. Minimum valid value is 0 or none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']), 'error')
                error_len = error_len + 1
            elif isinstance(register_conversion_item['precision'], int) and register_conversion_item['precision'] < 0:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s configuration for conversion name: %s. Minimum valid value is 0 or none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']), 'error')
                error_len = error_len + 1
    else:
        if param_name == 'precision':
            printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find %s configuration for conversion name %s. Defaulting to none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']), 'debug')
            mb_config_detail[item_index]['register_conversion'][conversion_item_index]['precision'] = 'none'
        else:
            printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find %s configuration.' % (item_index, conversion_item_index, param_name), 'error')
            error_len = error_len + 1

def main():
    """
    It's the MainThread process!
    All MODBUS device threads will be started from here.
    """
    mb_config_detail = []
    mb_config_files = 0

    # Looking for all *.modbus.yaml files in <base_dir>/config/slaves/ directory, representing EVC devices' MODBUS configuration.
    for slave_config in glob('config/slaves/*.modbus.yaml'):
        with open(slave_config, 'r') as mb_config:
            mb_config_files += 1
            printLog('Loading Modbus device configurations from %s...' % slave_config)
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
                        printLog('[Item %s] No Modbus RTU device port defined.' % item_index, 'error')
                        error_len = error_len + 1
                elif mb_config_check_item['type'] == 'rtuovertcp':
                    if 'port' not in mb_config_check_item or 'host' not in mb_config_check_item:
                        printLog('[Item %s] No Modbus RTU device host and port defined.' % item_index, 'error')
                        error_len = error_len + 1
                    elif isinstance(mb_config_check_item['port'], int) == False:
                        printLog('[Item %s] Invalid TCP port setting for Modbus RTU device.' % item_index, 'error')
                        error_len = error_len + 1
                elif mb_config_check_item['type'] == 'tcp':
                    if 'port' not in mb_config_check_item or 'host' not in mb_config_check_item:
                        printLog('[Item %s] No Modbus TCP device host and port defined.' % item_index, 'error')
                        error_len = error_len + 1
                elif mb_config_check_item['type'] == 'ascii':
                    if 'port' not in mb_config_check_item:
                        printLog('[Item %s] No Modbus ASCII device port defined.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s] Invalid Modbus device type (type: ) defined.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] No Modbus device type defined.')
                if 'port' in mb_config_check_item:
                    if 'host' in mb_config_check_item:
                        printLog('[Item %s] Assuming Modbus device type of RTU over TCP (type: rtuovertcp) on %s port %s.' % (item_index, mb_config_check_item['host'], mb_config_check_item['port']))
                        mb_config_detail[item_index]['type'] = 'rtu'
                    else:
                        printLog('[Item %s] Assuming Modbus device type of RTU (type: rtu) on port %s.' % (item_index, mb_config_check_item['port']))
                        mb_config_detail[item_index]['type'] = 'rtu'
                else:
                    printLog('[Item %s] Cannot assume Modbus device type.' % item_index, 'error')
                    error_len = error_len + 1

            # END - Sanity check for type, port and host configuration.

            # START - Sanity check for name configuration.

            if 'name' not in mb_config_check_item:
                printLog('[Item %s] Modbus device name (name: unique) must be specified.' % item_index, 'error')
                error_len = error_len + 1
            elif mb_config_check_item['name'] == "":
                printLog('[Item %s] Modbus device name (name: unique) cannot be blank.' % item_index, 'error')
                error_len = error_len + 1

            # END - Sanity check for name configuration.

            # START - Sanity check for timeout_seconds configuration.

            if 'timeout_seconds' in mb_config_check_item:
                if isinstance(mb_config_check_item['timeout_seconds'], int):
                    if mb_config_check_item['timeout_seconds'] < 1 or mb_config_check_item['timeout_seconds'] > 300:
                        printLog('[Item %s] Invalid Modbus device connection timeout (timeout_seconds: ). Valid setting is between 1 and 300 seconds.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s] Invalid Modbus device connection timeout (timeout_seconds: ). Valid setting is between 1 and 300 seconds.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Undefined Modbus device connection timeout (timeout_seconds: ). Using default setting (3 seconds).' % item_index)
                mb_config_detail[item_index]['timeout_seconds'] = 3

            # END - Sanity check for timeout_seconds configuration.

            # START - Sanity check for wait_milliseconds configuration.

            if 'wait_milliseconds' in mb_config_check_item:
                if isinstance(mb_config_check_item['wait_milliseconds'], int):
                    if mb_config_check_item['wait_milliseconds'] < 10 or mb_config_check_item['wait_milliseconds'] > 10000:
                        printLog('[Item %s] Invalid Modbus polling wait interval (wait_milliseconds: ). Valid setting is between 10 and 10000 milliseconds.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s] Invalid Modbus polling wait interval (wait_milliseconds: ). Valid setting is between 10 and 10000 milliseconds.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Undefined Modbus polling wait interval (wait_milliseconds: ). Using default setting (100 milliseconds).' % item_index)
                mb_config_detail[item_index]['wait_milliseconds'] = 100

            # END - Sanity check for wait_milliseconds configuration.

            # START - Sanity check for current_log configuration.

            if 'current_log' in mb_config_check_item:

                # START - Sanity check for current_log --> scan_interval_ms configuration.

                if 'scan_interval_ms' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['scan_interval_ms'], int):
                        if mb_config_check_item['current_log']['scan_interval_ms'] < 1000:
                            printLog('[Item %s - current_log] Invalid polling interval configuration (scan_interval_ms: ). Valid minimum setting is 1000 milliseconds.' % item_index, 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - current_log] Invalid polling interval configuration (scan_interval_ms: ). Valid minimum setting is 1000 milliseconds.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] Unable to find polling interval configuration (scan_interval_ms: ).' % item_index, 'error')
                    error_len = error_len + 1

                # END - Sanity check for current_log --> scan_interval_ms configuration.

                # START - Sanity check for current_log --> debug configuration.

                if 'debug' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['debug'], bool) == False:
                        printLog('[Item %s - current_log] Invalid debug configuration (debug: ). Valid configuration are boolean: True or False.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] No debug configuration found. Assuming debug: False.' % item_index)
                    mb_config_detail[item_index]['current_log']['debug'] = False

                # END - Sanity check for current_log --> debug configuration.

                # START - Sanity check for current_log --> group_ids configuration.

                if 'group_ids' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['group_ids'], list) == False:
                        printLog('[Item %s - current_log] Invalid group_ids configuration (group_ids: ). It should be a list.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] No group_ids configuration found.' % item_index, 'error')
                    error_len = error_len + 1

                # END - Sanity check for current_log --> group_ids configuration.

                # Create Group ID list for current_log if --create-tables is called.
                if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
                    group_id_list['current_log'] = mb_config_check_item['current_log']['group_ids']
                    register_conversion_fields.update({'current_log': []})

            else:
                printLog('[Item %s] Unable to find current_log configuration.' % item_index, 'error')
                error_len = error_len + 1

            # END - Sanity check for current_log configuration.

            # START - Sanity check for hourly_log, daily_log, monthly_log configuration.
            for current_archive_log in ARCHIVE_LOG_LIST:
                if current_archive_log in mb_config_check_item:

                    # START - Sanity check for hourly_log, daily_log, monthly_log --> max_retention configuration.

                    if 'max_retention' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['max_retention'], int):
                            if mb_config_check_item[current_archive_log]['max_retention'] < 1:
                                printLog('[Item %s - %s] The minimum value of max_retention is 1. Disabling it.' % (item_index, current_archive_log))
                                mb_config_detail[item_index][current_archive_log]['max_retention'] = 0
                        else:
                            printLog('[Item %s - %s] Invalid max_retention configuration (max_retention: ) found. The minimum valid value should be 1.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        mb_config_detail[item_index][current_archive_log]['max_retention'] = 0

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> max_retention configuration.

                    # START - Sanity check for hourly_log, daily_log, monthly_log --> debug configuration.

                    if 'debug' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['debug'], bool) == False:
                            printLog('[Item %s - %s] Invalid debug configuration (debug: ). The valid value are boolean: true or false.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - %s] No debug configuration found. Assuming debug: False.' % (item_index, current_archive_log))
                        mb_config_detail[item_index][current_archive_log]['debug'] = False

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> debug configuration.

                    # START - Sanity check for hourly_log, daily_log, monthly_log --> group_ids configuration.

                    if 'group_ids' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['group_ids'], list) == False:
                            printLog('[Item %s - %s] Invalid group_ids configuration (group_ids: ). It should be a list.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - current_log] No group_ids configuration found.' % item_index, 'error')
                        error_len = error_len + 1

                    # END - Sanity check for hourly_log, daily_log, monthly_log --> group_ids configuration.

                    # Create group_id list for hourly_log, daily_log, monthly_log.
                    group_id_list[current_archive_log] = mb_config_check_item[current_archive_log]['group_ids']

                else:
                    printLog('[Item %s] Unable to find %s configuration. Disabling it.' % (item_index, current_archive_log))
                    ARCHIVE_LOG_ENABLED[current_archive_log] = False

            # END - Sanity check for hourly_log, daily_log, monthly_log configuration.

            # START - Sanity check for register_group configuration.

            if 'register_group' in mb_config_check_item:
                if isinstance(mb_config_check_item['register_group'], list) == True:
                    for grp_item_index, register_group_item in enumerate(mb_config_check_item['register_group']):
                        # START - Sanity check for group_id, slave, address, count, type configuration.
                        for param_name in ['group_id',
                                                'slave',
                                                'address',
                                                'count',
                                                'type']:
                            register_group_paramcheck(param_name = param_name, grp_item_index = grp_item_index, register_group_item=register_group_item, mb_config_check_item=mb_config_check_item, item_index=item_index)
                        # END - Sanity check for group_id, slave, address, count, type configuration.
                else:
                    printLog('[Item %s] Invalid register_group configuration (register_group: ). It should be a list.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Unable to find register_group configuration.' % item_index, 'error')
                error_len = error_len + 1

            # END - Sanity check for register_conversion configuration.

            # START - Sanity check for register_conversion configuration.

            if 'register_conversion' in mb_config_check_item:
                
                if isinstance(mb_config_check_item['register_conversion'], list) == True:
                    for grp_item_index, register_conversion_item in enumerate(mb_config_check_item['register_conversion']):
                        # START - Sanity check for name, group_ids, registers, data_type, swap, precision configuration.

                        for param_name in ['name',
                                            'group_ids',
                                            'registers',
                                            'data_type',
                                            'swap',
                                            'precision']:
                            register_conversion_paramcheck(param_name=param_name, conversion_item_index=grp_item_index, mb_config_check_item=mb_config_check_item, register_conversion_item=register_conversion_item, mb_config_detail=mb_config_detail, item_index=item_index)

                        if register_conversion_item['name'] == mb_config_check_item['current_log']['evc_time_regname']:
                            evctime_reg[mb_config_check_item['name']] = {
                                'name': register_conversion_item['name'],
                                'data_type': register_conversion_item['data_type']
                            }

                        # END - Sanity check for name, group_ids, registers, data_type, swap, precision configuration.

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
                    printLog('[Item %s] Invalid register_conversion configuration (register_conversion: ). It should be a list.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Unable to find register_conversion configuration.' % item_index, 'error')
                error_len = error_len + 1

            # END - Sanity check for register_conversion configuration.
    else:
        printLog('No Modbus configuration found.', 'error')
        error_len = error_len + 1

    if error_len > 0:
        app_exit(1)
    elif mb_config_files == 0:
        printLog("No Modbus device configuration file found, aborting.")
        app_exit(1)
    else:
        printLog('Modbus device configuration(s) loaded successfully.')

        # Delete all unneeded variable after the sanity check is done.
        del mb_config_check_all

    # END - Modbus config sanity check and default value.

    # DB config sanity check, tables existence and default value.
    db_params = db_config_check()

    if db_params == False:
        app_exit(1)

    # START -- Create tables if --create-tables argument is passed.
    if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
        from arkanod.evc.db_tables_create import init_create_tables
        init_create_tables(db_params[0], register_conversion_fields, mb_config_check_item)
        return
    # END -- Create tables if --create-tables argument is passed.

    # MODBUS device threads start here.
    threads = []

    # Register some OS signals received to be processed by the configured handler.
    for current_os_signal in [SIGINT, SIGHUP, SIGTERM]:
        os_signal(current_os_signal, signal_term_handler(threads=threads))

    # MODBUS poll each EVC device ID
    for mb_config_item in mb_config_detail:
        thread = device_read(mb_config_item, evctime_reg[mb_config_item['name']], db_params[0])
        thread.name = mb_config_item['name']
        threads.append(thread)
        thread.start()

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

        try:
            sleep(0.1)
        except:
            for thread in threads:
                thread.shutdown()
            return

if __name__ == '__main__':
    main()
