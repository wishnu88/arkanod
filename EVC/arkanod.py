#!/usr/bin/env python3

import yaml
import mariadb
import sys
import logging
from signal import (signal as os_signal, SIGTERM, SIGINT, SIGHUP)
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.transaction import (ModbusRtuFramer, ModbusAsciiFramer, ModbusSocketFramer)
from time import (sleep, time as millis)
from datetime import (datetime, timezone, timedelta)

modbus_type_list = [
    'rtuovertcp',
    'rtu',
    'tcp',
    'ascii'
]

register_type_list = [
    'coil',
    'input',
    'holding'
]

swap_type_list = [
    'byte',
    'word',
    'word_byte',
    'none'
]

data_type_list = [
    'float16',
    'float32',
    'float64',
    'int8',
    'int16',
    'int32',
    'int64',
    'string',
    'uint8',
    'uint16',
    'uint32',
    'uint64',
    'dt1',
    'dt2',
    'bits',
    'ignore'
]

archive_log_list = [
    'hourly_log',
    'daily_log',
    'monthly_log'
]

archive_log_enabled = {
    'hourly_log': True,
    'daily_log': True,
    'monthly_log': True,
}

archive_log_failed = {
    'hourly_log': False,
    'daily_log': False,
    'monthly_log': False,
}

group_id_list = {}

if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
    register_conversion_fields = {archive_log: [] for archive_log in archive_log_list}

isRunning = True

def printLog(msg: str, level: str = 'info'):
    if logging.getLogger().hasHandlers():
        if level == 'info':
            logging.info(msg)
        elif level == 'debug':
            logging.debug(msg)
        elif level == 'error':
            logging.error(msg)
        elif level == 'critical':
            logging.critical(msg)
    else:
        print(msg)

def db_close():
    global db_conn

    if 'db_conn' in globals():
        printLog("Closing MariaDB database...")
        db_conn.close()
        del db_conn

def modbus_close():
    global client

    if 'client' in globals() and isinstance(client, object) and len(client) > 0:
        printLog("Disconnecting from Modbus devices...")
        for client_conn in client:
            if client[client_conn].connected == True:
                client[client_conn].close()
        del client

def app_exit(exitVal: int = 0):
    global isRunning

    isRunning = False

    modbus_close()
    db_close()
    printLog('Exited with error(s).' if exitVal > 0 else 'Graceful exit done.')   
    sys.exit(exitVal)

def convert_registers(registers, swap_type: str = "none"):
    if swap_type == 'word':
        byte_order = Endian.BIG
        word_order = Endian.LITTLE
    elif swap_type == 'word_byte':
        byte_order = word_order = Endian.BIG
    else:
        byte_order = Endian.LITTLE
        word_order = Endian.BIG

    return BinaryPayloadDecoder.fromRegisters(registers, byte_order, wordorder=word_order) if swap_type != "none" else BinaryPayloadDecoder.fromRegisters(registers)

def decode_results(results, data_type):

    if data_type == 'ignore':
        decoded = results.skip_bytes(8)
    elif data_type == 'bits':
        decoded = results.decode_bits()
    elif data_type == 'float16':
        decoded = results.decode_16bit_float()
    elif data_type == 'float32':
        decoded = results.decode_32bit_float()
    elif data_type == 'float64':
        decoded = results.decode_64bit_float()
    elif data_type == 'int8':
        decoded = results.decode_8bit_int()
    elif data_type == 'int16':
        decoded = results.decode_16bit_int()
    elif data_type == 'int32':
        decoded = results.decode_32bit_int()
    elif data_type == 'int64':
        decoded = results.decode_64bit_int()
    elif data_type == 'string':
        decoded = results.decode_string()
    elif data_type == 'uint8':
        decoded = results.decode_8bit_uint()
    elif data_type == 'uint16':
        decoded = results.decode_16bit_uint()
    elif data_type == 'uint32':
        decoded = results.decode_32bit_uint()
    elif data_type == 'uint64':
        decoded = results.decode_64bit_uint()
    elif data_type == 'dt1':
        decoded = results.decode_32bit_uint()
    elif data_type == 'dt2':
        hex_values = ["{:04x}".format(register) for register in results]
        decoded = "".join(hex_values)

    return decoded

def mb_connect(type, port: str, host: str = None, mb_timeout: int = None):
    if isRunning == False:
        return

    if type in ['rtuovertcp','tcp']:        
        try:
            printLog("Connecting to %s port %s..." % (host, port))
            if 'ModbusTcpClient' not in sys.modules:
                from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(host=host, port=int(port), framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            printLog("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            printLog('Unable to establish connection to %s port %s.' % (host, port), 'error')
    elif type == 'rtu':        
        try:
            printLog("Connecting to port %s..." % port)
            if 'ModbusSerialClient' not in sys.modules:
                from pymodbus.client import ModbusSerialClient
            client = ModbusSerialClient(port=port, framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            printLog("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            printLog('Unable to establish connection to %s port %s.' % (host, port), 'error')

def get_log_group_ids(register_group_ids) -> list:
    register_group_address = []

    for register_group in mb_config_item['register_group']:

        """ Skip group_id not included in group_ids """
        if register_group['group_id'] not in register_group_ids:
            continue

        register_group_address.append(register_group)

    return register_group_address

def get_evc_log(register_groups, slaveID = None) -> dict:
    global client
    
    register_group_address = {}
    register_items = {}
    register_slave_ids = {}

    for register_group in register_groups:
        
        current_slave_id = int(register_group['slave'])
        register_items[current_slave_id] = {}
        if slaveID is not None and slaveID != current_slave_id:
            continue
        register_gap = 0 if 'gap' not in register_group else register_group['gap']

        """ Modbus read delay """
        sleep((mb_config_item['wait_milliseconds'] / 1000))
        try:
            if register_group['type'] == "input":
                result = client[mb_config_item['name']].read_input_registers(int(register_group['address']) + register_gap, register_group['count'], slave=current_slave_id)
            elif register_group['type'] == "holding":
                result = client[mb_config_item['name']].read_holding_registers(int(register_group['address']) + register_gap, register_group['count'], slave=current_slave_id)
        except:
            printLog('Unable to poll Modbus device on %s port %s with slave ID %s. Moving on...' % (mb_config_item['host'] if 'host' in mb_config_item else 'local', mb_config_item['port'], register_group['slave']), 'error')
            sleep(mb_config_item['timeout_seconds'])
            continue

        if hasattr(result, 'registers') == False:
            printLog('Unexpected response from Modbus device on %s port %s with slave ID %s.' % (mb_config_item['host'] if 'host' in mb_config_item else 'local', mb_config_item['port'], register_group['slave']), 'error')
            sleep(mb_config_item['timeout_seconds'])
            if client[mb_config_item['name']].connected == False:
                printLog('Disconnected from %s port %s.' % (mb_config_item['host'] if 'host' in mb_config_item else 'local', mb_config_item['port']), 'error')
                client[mb_config_item['name']] = mb_connect(mb_config_item['type'], host=mb_config_item['host'], port=mb_config_item['port'], mb_timeout=mb_config_item['timeout_seconds'])
                current_log_timers[mb_config_item['name']] = 0
            break
        
        if len(result.registers) == register_group['count']:
            register_addr_map = register_group['address'] + register_gap
            register_group_values = {}
            for result_map in result.registers:
                register_group_values[register_addr_map] = result_map
                register_addr_map = register_addr_map + 1
        else:
            continue

        register_group_address[register_group['group_id']] = register_group_values    

        for register_conversion in mb_config_item['register_conversion']:
            group_exists = 0
            for group_id in register_conversion['group_ids']:
                if group_id == register_group['group_id']:
                    group_exists = 1
                    break
            
            if group_exists == 0:
                continue

            current_registers = []
            register_value_precision = 0 if 'precision' not in register_conversion else register_conversion['precision']

            for register_i in range(int(register_conversion['registers'][0]) + register_gap, int(register_conversion['registers'][1]) + register_gap + 1):
                try:
                    current_registers.append(register_group_address[register_group['group_id']][register_i])
                except:
                    continue

            if len(current_registers) > 0:
                register_value = decode_results(current_registers if register_conversion['data_type'] in ['dt1', 'dt2'] else convert_registers(current_registers, register_conversion['swap'] if 'swap' in register_conversion else None), register_conversion['data_type'])
                register_items[current_slave_id][register_conversion['name']] = round(register_value, register_value_precision) if register_value_precision != "none" else register_value
                register_slave_ids[register_conversion['name']] = current_slave_id

    return {'items': register_items if slaveID is None else register_items[slaveID], 'slaveIDs': register_slave_ids}

def send_archive_log(deviceID: int, group_ids, kind: str, retention: int = 0, slaveID: int = 1) -> dict:
    success_status = 0

    if kind in archive_log_list:
        archive_log_group_ids = get_log_group_ids(group_ids)
        
        all_archive_log_items = []
        for n_iter in range(0 if retention == 0 else 1, retention + 1):
            if retention > 0:
                for group_id_index in range(0, len(archive_log_group_ids)):
                    archive_log_group_ids[group_id_index]['gap'] = n_iter * archive_log_group_ids[group_id_index]['count']

            archive_log_items = get_evc_log(archive_log_group_ids, slaveID)['items']

            if mb_config_item[kind]['debug'] is True:
                print(archive_log_items)

            if retention > 0:
                for group_id_index in range(0, len(archive_log_group_ids)):
                    del archive_log_group_ids[group_id_index]['gap']

            try:
                q_insert_archive = "INSERT IGNORE INTO %s (deviceID, %s) VALUES (%s)s)" % (db_config_detail[0]['tbl_prefix'] + '_' + kind, ', '.join(archive_log_items), str(deviceID) + ", %(" + ")s, %(".join([item_name for item_name in archive_log_items]))               
                db_cur.execute(q_insert_archive, archive_log_items)
                if db_cur.rowcount > 0:
                    all_archive_log_items.append(archive_log_items)
            except Exception as e:
                printLog(e, 'error')
                if retention == 0:
                    success_status = 2
            else:
                if retention == 0:
                    success_status = 1
        
        return {'items': all_archive_log_items, 'status': success_status}

def send_current_log(deviceID: int, items: dict = None, insert_log = False) -> bool:
    if insert_log == True:
        try:
            q_insert_current = "INSERT INTO %s_current_log (deviceID) VALUES (?)" % db_config_detail[0]['tbl_prefix']
            db_cur.execute(q_insert_current, (deviceID,))
        except:
            return False
    else:
        try:
            """ Create current log query template using dictionary """
            q_update_current_log = "UPDATE %s_current_log SET " % db_config_detail[0]['tbl_prefix']
            q_update_items = []
            for item_name in items:
                q_update_items.append("%s = %%(%s)s" % (item_name, item_name))
            q_update_current_log += ", ".join(q_update_items) + " WHERE deviceID = %s" % deviceID

            db_cur.execute(q_update_current_log, items)
        except Exception as e:
            printLog(e, 'error')
            return False
    return True

def dt_utc_to_current(datetime_str: int, data_type: str = 'dt1') -> datetime:
    data_type = 'dt1' if data_type == 'dt2' and datetime_str == 0 else data_type

    if data_type == 'dt1':
        return datetime.strptime(str(datetime.fromtimestamp(datetime_str, timezone.utc)), '%Y-%m-%d %H:%M:%S%z')
    elif data_type == 'dt2':             
        return datetime.strptime(datetime_str, '%y%m%d%H%M%S')

def signal_term_handler(signal, frame):
    if signal in [SIGTERM, SIGINT]:
        app_exit()
    elif signal == SIGHUP:
        global app_stage
        app_stage = 0

def register_group_paramcheck(param_name: str, grp_item_index: int):
    global mb_config_check_item, error_len, register_group_item

    log_types = archive_log_list[:]
    log_types.append('current_log')

    if param_name in register_group_item:
        if param_name == 'group_id':
            exists_count = 0
            for current_log_type in log_types:
                if register_group_item[param_name] in mb_config_check_item[current_log_type]['group_ids']:
                    exists_count = exists_count + 1
            
            if exists_count == 0:
                printLog('[Item %s - register_group - Group Item %s] Unable to find %s in any log type group_ids.' % (item_index, grp_item_index, param_name), 'error')
                error_len = error_len + 1
        
        if param_name != 'type' and isinstance(register_group_item[param_name], int) == False:
            printLog('[Item %s - register_group - Group Item %s] Invalid %s settings. It should be an integer.' % (item_index, grp_item_index, param_name), 'error')
            error_len = error_len + 1
        elif param_name == 'type' and register_group_item[param_name] not in register_type_list:
            printLog('[Item %s - register_group - Group Item %s] Invalid Modbus register type option (type: %s). Supported options are: %s.' % (item_index, grp_item_index, register_group_item[param_name], modbus_type_list), 'error')
            error_len = error_len + 1
    else:
        printLog('[Item %s - register_group - Group Item %s] Unable to find %s settings.' % (item_index, grp_item_index, param_name), 'error')
        error_len = error_len + 1

def register_conversion_paramcheck(param_name: str, conversion_item_index: int):
    global mb_config_check_item, error_len, register_conversion_item, mb_config_detail
    """Sanity check for name, group_id, registers, data_type, swap, precision settings"""
    if param_name in register_conversion_item:
        if param_name == 'group_ids':
            for curr_group_id in register_conversion_item['group_ids']:
                exists_count = 0
                for current_register_group in mb_config_check_item['register_group']:
                    if curr_group_id == current_register_group['group_id']:
                        exists_count = 1
                        break

                if exists_count == 0:
                    printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find group_ids: %s in any register_group.' % (item_index, conversion_item_index, curr_group_id), 'error')
                    error_len = error_len + 1

        elif param_name == 'registers':
            if isinstance(register_conversion_item['registers'], list) == False:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. It should be a list [start_reg_addr, end_reg_addr].' % (item_index, conversion_item_index, 'registers', register_conversion_item['name']), 'error')
                error_len = error_len + 1
            elif register_conversion_item['registers'][0] > register_conversion_item['registers'][1]:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. The start_reg_addr should be less than end_reg_addr.' % (item_index, conversion_item_index, 'registers', register_conversion_item['name']), 'error')
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
                                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. Modbus register address not in the correct range of group_id %s (should be between %s - %s).' % (item_index, conversion_item_index, 'registers', register_conversion_item['name'], curr_group_id, regnum['start'], regnum['end']), 'error')
                                error_len = error_len + 1
        elif param_name == 'data_type' and register_conversion_item['data_type'] not in data_type_list:
            printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. Valid options are: %s.' % (item_index, conversion_item_index, 'data_type', register_conversion_item['name'], data_type_list), 'error')
            error_len = error_len + 1
        elif param_name == 'swap' and register_conversion_item['swap'] not in swap_type_list:
            printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. Valid options are: %s.' % (item_index, conversion_item_index, 'swap', register_conversion_item['name'], swap_type_list), 'error')
            error_len = error_len + 1
        elif param_name == 'precision':
            if isinstance(register_conversion_item['precision'], int) == False and register_conversion_item['precision'] != 'none':
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. Minimum valid value is 0 or none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']), 'error')
                error_len = error_len + 1
            elif isinstance(register_conversion_item['precision'], int) and register_conversion_item['precision'] < 0:
                printLog('[Item %s - register_conversion - Group Item %s] Invalid %s settings for conversion name: %s. Minimum valid value is 0 or none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']), 'error')
                error_len = error_len + 1
    else:
        if param_name == 'precision':
            printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find %s settings for conversion name %s. Defaulting to none.' % (item_index, conversion_item_index, 'precision', register_conversion_item['name']))
            mb_config_detail[item_index]['register_conversion'][conversion_item_index]['precision'] = 'none'
        else:
            printLog('[Item %s - register_conversion - Conversion Item %s] Unable to find %s settings.' % (item_index, conversion_item_index, param_name), 'error')
            error_len = error_len + 1

for current_os_signal in [SIGINT, SIGHUP, SIGTERM]:
    os_signal(current_os_signal, signal_term_handler)

app_stage = 0

while isRunning:

    if 'glob' not in sys.modules:
        from glob import glob

    mb_config_detail = []
    for slave_config in glob('slaves/*.modbus.yaml'):
        with open(slave_config, 'r') as mb_config:
            printLog('Loading Modbus devices settings from %s...' % slave_config)
            mb_config_detail += yaml.safe_load(mb_config)

    mb_config_check_all = mb_config_detail

    if 'mb_config_check_all' in vars():
        """ START - Modbus config sanity check and default value """

        error_len = 0

        for item_index, mb_config_check_item in enumerate(mb_config_check_all):
            """ START - Sanity check for type, port and host settings """
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

            """ END - Sanity check for type, port and host settings """

            """ START - Sanity check for name settings """

            if 'name' not in mb_config_check_item:
                printLog('[Item %s] Modbus device name (name: unique) must be specified.' % item_index, 'error')
                error_len = error_len + 1
            elif mb_config_check_item['name'] == "":
                printLog('[Item %s] Modbus device name (name: unique) cannot be blank.' % item_index, 'error')
                error_len = error_len + 1

            """ END - Sanity check for name settings """

            """ START - Sanity check for timeout_seconds settings """

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

            """ END - Sanity check for timeout_seconds settings """

            """ START - Sanity check for wait_milliseconds settings """

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

            """ END - Sanity check for wait_milliseconds settings """

            """ START - Sanity check for current_log settings """

            if 'current_log' in mb_config_check_item:

                """ START - Sanity check for current_log --> scan_interval_ms settings """

                if 'scan_interval_ms' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['scan_interval_ms'], int):
                        if mb_config_check_item['current_log']['scan_interval_ms'] < 1000:
                            printLog('[Item %s - current_log] Invalid polling interval settings (scan_interval_ms: ). Valid minimum setting is 1000 milliseconds.' % item_index, 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - current_log] Invalid polling interval settings (scan_interval_ms: ). Valid minimum setting is 1000 milliseconds.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] Unable to find polling interval settings (scan_interval_ms: ).' % item_index, 'error')
                    error_len = error_len + 1

                """ END - Sanity check for current_log --> scan_interval_ms settings """

                """ START - Sanity check for current_log --> debug settings """

                if 'debug' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['debug'], bool) == False:
                        printLog('[Item %s - current_log] Invalid debug settings (debug: ). Valid settings are boolean: True or False.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] No debug settings found. Assuming debug: False.' % item_index)
                    mb_config_detail[item_index]['current_log']['debug'] = False

                """ END - Sanity check for current_log --> debug settings """

                """ START - Sanity check for current_log --> group_ids settings """

                if 'group_ids' in mb_config_check_item['current_log']:
                    if isinstance(mb_config_check_item['current_log']['group_ids'], list) == False:
                        printLog('[Item %s - current_log] Invalid group_ids settings (group_ids: ). It should be a list.' % item_index, 'error')
                        error_len = error_len + 1
                else:
                    printLog('[Item %s - current_log] No group_ids settings found.' % item_index, 'error')
                    error_len = error_len + 1

                """ END - Sanity check for current_log --> group_ids settings """

                """ Create Group ID list for current_log if --create-tables is called """
                if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
                    group_id_list['current_log'] = mb_config_check_item['current_log']['group_ids']
                    register_conversion_fields.update({'current_log': []})

            else:
                printLog('[Item %s] Unable to find current_log settings.' % item_index, 'error')
                error_len = error_len + 1

            """ END - Sanity check for current_log settings """

            """ START - Sanity check for hourly_log, daily_log, monthly_log settings """
            for current_archive_log in archive_log_list:
                if current_archive_log in mb_config_check_item:

                    """ START - Sanity check for hourly_log, daily_log, monthly_log --> max_retention settings """

                    if 'max_retention' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['max_retention'], int):
                            if mb_config_check_item[current_archive_log]['max_retention'] < 1:
                                printLog('[Item %s - %s] The minimum settings of max_retention is 1. Disabling it.' % (item_index, current_archive_log))
                                mb_config_detail[item_index][current_archive_log]['max_retention'] = 0
                        else:
                            printLog('[Item %s - %s] Invalid max_retention settings (max_retention: ) found. The minimum valid value should be 1.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        mb_config_detail[item_index][current_archive_log]['max_retention'] = 0

                    """ END - Sanity check for hourly_log, daily_log, monthly_log --> max_retention settings """

                    """ START - Sanity check for hourly_log, daily_log, monthly_log --> debug settings """

                    if 'debug' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['debug'], bool) == False:
                            printLog('[Item %s - %s] Invalid debug settings (debug: ). Valid settings are boolean: True or False.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - %s] No debug settings found. Assuming debug: False.' % (item_index, current_archive_log))
                        mb_config_detail[item_index][current_archive_log]['debug'] = False

                    """ END - Sanity check for hourly_log, daily_log, monthly_log --> debug settings """

                    """ START - Sanity check for hourly_log, daily_log, monthly_log --> group_ids settings """

                    if 'group_ids' in mb_config_check_item[current_archive_log]:
                        if isinstance(mb_config_check_item[current_archive_log]['group_ids'], list) == False:
                            printLog('[Item %s - %s] Invalid group_ids settings (group_ids: ). It should be a list.' % (item_index, current_archive_log), 'error')
                            error_len = error_len + 1
                    else:
                        printLog('[Item %s - current_log] No group_ids settings found.' % item_index, 'error')
                        error_len = error_len + 1

                    """ END - Sanity check for hourly_log, daily_log, monthly_log --> group_ids settings """

                    """ Create Group ID list for hourly_log, daily_log, monthly_log """
                    group_id_list[current_archive_log] = mb_config_check_item[current_archive_log]['group_ids']

                else:
                    printLog('[Item %s] Unable to find %s settings. Disabling it.' % (item_index, current_archive_log))
                    archive_log_enabled[current_archive_log] = False

            """ END - Sanity check for hourly_log, daily_log, monthly_log settings """

            """ START - Sanity check for register_group settings """

            if 'register_group' in mb_config_check_item:
                if isinstance(mb_config_check_item['register_group'], list) == True:
                    for grp_item_index, register_group_item in enumerate(mb_config_check_item['register_group']):
                        """ START - Sanity check for group_id, slave, address, count, type settings """
                        for param_name in ['group_id',
                                                'slave',
                                                'address',
                                                'count',
                                                'type']:
                            register_group_paramcheck(param_name, grp_item_index)
                        """ END - Sanity check for group_id, slave, address, count, type settings """
                else:
                    printLog('[Item %s] Invalid register_group settings (register_group: ). It should be a list.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Unable to find register_group settings.' % item_index, 'error')
                error_len = error_len + 1

            """ END - Sanity check for register_conversion settings """

            """ START - Sanity check for register_conversion settings """

            if 'register_conversion' in mb_config_check_item:
                
                if isinstance(mb_config_check_item['register_conversion'], list) == True:
                    for grp_item_index, register_conversion_item in enumerate(mb_config_check_item['register_conversion']):
                        """ START - Sanity check for name, group_ids, registers, data_type, swap, precision settings """
                        for param_name in ['name',
                                            'group_ids',
                                            'registers',
                                            'data_type',
                                            'swap',
                                            'precision']:
                            register_conversion_paramcheck(param_name, grp_item_index)

                        if 'evctime_reg' not in vars() and register_conversion_item['name'] == mb_config_check_item['current_log']['evc_time_regname']:
                            evctime_reg = {
                                'name': register_conversion_item['name'],
                                'data_type': register_conversion_item['data_type']
                            }

                        """ END - Sanity check for name, group_ids, registers, data_type, swap, precision settings """

                        """ List items for current_log and archive log table creation """
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
                    printLog('[Item %s] Invalid register_conversion settings (register_conversion: ). It should be a list.' % item_index, 'error')
                    error_len = error_len + 1
            else:
                printLog('[Item %s] Unable to find register_conversion settings.' % item_index, 'error')
                error_len = error_len + 1

            """ END - Sanity check for register_conversion settings """
    else:
        printLog('No Modbus configuration found.', 'error')
        error_len = error_len + 1

    if error_len > 0:
        app_exit(1)
    else:
        printLog('Modbus devices settings loaded successfully.')
        del mb_config_check_all

    """ END - Modbus config sanity check and default value """
        

    with open('db.yaml', 'r') as db_config:
        printLog('Loading MariaDB database settings from db.yaml...')
        db_config_check = db_config_detail = yaml.safe_load(db_config)

        """ START - DB config sanity check and default value """

        if len(db_config_check) > 0:
            
            for db_item_index, db_instance in enumerate(db_config_check):
                for db_param_name in ['db_instance','db_host','db_username','db_password','db_name']:
                    if db_param_name not in db_instance:
                        printLog('[DB Item %s] Unable to find %s settings' + ' for instance %s' if db_param_name != 'db_instance' else '' + '.' % (db_item_index, db_param_name, db_instance['db_instance'] if db_param_name != 'db_instance' else None), 'error')
                        error_len = error_len + 1
                    elif db_param_name in db_instance and db_instance[db_param_name] == "":
                        printLog('[DB Item %s] Invalid %s settings' + ' for instance %s' if db_param_name != 'db_instance' else '' + '.' % (db_item_index, db_param_name, db_instance['db_instance'] if db_param_name != 'db_instance' else None), 'error')
                        error_len = error_len + 1

                if 'db_port' not in db_instance:
                    printLog('[DB Item %s] Unable to find db_port settings. Assuming TCP/3306 as the DB port.' % db_item_index)
                    db_config_detail[db_item_index]['db_port'] = 3306
                elif 'db_port' in db_instance:
                    if (isinstance(db_instance['db_port'], int) and (db_instance['db_port'] < 1 or db_instance['db_port'] > 65535)) or isinstance(db_instance['db_port'], int) == False:
                        printLog('[DB Item %s] Invalid db_port settings.' % db_item_index, 'error')
                        error_len = error_len + 1

        if error_len > 0:
            app_exit(1)
        else:
            printLog('MariaDB database settings loaded successfully.')
            del db_config_check
            del error_len

        """ END - DB config sanity check and default value """

        try:
            db_conn = mariadb.connect(
                host=db_config_detail[0]['db_host'],
                port=db_config_detail[0]['db_port'],
                user=db_config_detail[0]['db_username'],
                password=db_config_detail[0]['db_password'],
                database=db_config_detail[0]['db_name'],
                autocommit=True,
                reconnect=True)

            """ Instantiate MariaDB Cursor """
            db_cur = db_conn.cursor()

        except mariadb.Error as e:
            printLog(f"Error connecting to the database: {e}", 'critical')
            app_exit(1)

        """ START -- Create tables if --create-tables argument is passed """
        if len(sys.argv) > 1 and sys.argv[1] == '--create-tables':
            data_type = {
                'float16': 'float',
                'float32': 'float',
                'float64': 'double',
                'int8': 'tinyint',
                'int16': 'smallint',
                'int32': 'int',
                'int64': 'bigint',
                'uint8': 'tinyint UNSIGNED',
                'uint16': 'smallint UNSIGNED',
                'uint32': 'int UNSIGNED',
                'uint64': 'bigint UNSIGNED',
                'string':'text',
                'dt1': 'datetime',
                'dt2': 'datetime',
                'bits': 'bit(8)'
            }

            def check_table_exists(table_name: str) -> bool:
                db_cur.execute('SHOW TABLE STATUS FROM %s WHERE Name = ?' % db_config_detail[0]['db_name'], [table_name])
                if db_cur.rowcount > 0:
                    return True
                return False

            def create_table_exec(table_name: str, query: str):
                try:
                    db_cur.execute(query)
                except Exception as e:
                    printLog(e, 'error')
                else:
                    printLog('Table %s is successfully created.' % table_name)

            oper_tables = {
                'devices': "(`id` int AUTO_INCREMENT PRIMARY KEY, `mbmaster_name` varchar(30) NOT NULL, `slaveID` tinyint NOT NULL DEFAULT 1, DeviceCreated DATETIME DEFAULT current_timestamp(), LastUpdated DATETIME DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP()) ENGINE=MyISAM DEFAULT CHARSET=utf8mb4",
                'request_log': "(`id` BIGINT AUTO_INCREMENT PRIMARY KEY, `deviceID` int NOT NULL, `archiveLog` tinyint NOT NULL, `logRetention` smallint NOT NULL, `requestStatus` tinyint NOT NULL DEFAULT 0, `RequestCreated` datetime NOT NULL DEFAULT current_timestamp(), `LastUpdated` datetime NOT NULL DEFAULT current_timestamp() ON UPDATE current_timestamp()) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
            }

            for oper_table in oper_tables:
                table_name = db_config_detail[0]['tbl_prefix'] + '_' + oper_table
                if check_table_exists(table_name):
                    printLog('Table %s is already exists, skipping.' % table_name)
                    continue

                create_table_exec(table_name, "CREATE TABLE %s " % table_name + oper_tables[oper_table])

                if oper_table == 'devices':
                    try:
                        db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `unique_dev` (`mbmaster_name`,`slaveID`)' % table_name)
                    except:
                        printLog("Failed to create index for table %s. Insufficient privilege?" % table_name, 'error')

            for log_table in register_conversion_fields:
                table_name = db_config_detail[0]['tbl_prefix'] + '_' + log_table
                fields_created = []
                table_fields = []
                if check_table_exists(table_name):
                    printLog('Table %s is already exists, skipping.' % table_name)
                    continue

                q_create_table = ("CREATE TABLE %s (`id` %sINT AUTO_INCREMENT PRIMARY KEY, deviceID INT NOT NULL, " % (table_name, 'BIG' if log_table == 'hourly_log' else ''))
                for item_field in register_conversion_fields[log_table]:
                    if item_field['item'] not in fields_created:
                        fields_created.append(item_field['item'])
                        table_fields.append("`" + item_field['item'] + "` %s" % data_type[item_field['data_type']])

                q_create_table += ", ".join(table_fields) + ", LastUpdated DATETIME DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP()) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4"
                create_table_exec(table_name, q_create_table)

                if log_table != "current_log":
                    try:
                        db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `unique_log` (`deviceID`,`%s`)' % (table_name, mb_config_check_item[log_table]['log_time_regname']))
                    except:
                        printLog("Failed to create index for table %s. Insufficient privilege?" % table_name, 'error')
            
            app_exit(0)
        """ END -- Create tables if --create-tables argument is passed """

    current_log_timers = {}
    for mb_config_item in mb_config_detail:
        current_log_timers[mb_config_item['name']] = 0

    client = {}
    current_device_id = {}
    last_dtu = {}

    app_stage = 1
    while app_stage == 1:
        for mb_config_item in mb_config_detail:
            if mb_config_item['name'] not in client or (mb_config_item['name'] in client and hasattr(client[mb_config_item['name']], 'connected') and client[mb_config_item['name']].connected == False):

                if mb_config_item['name'] in client:
                    printLog('Disconnected from %s port %s.' % (mb_config_item['host'] if 'host' in mb_config_item else 'local', mb_config_item['port']), 'error')
                
                client[mb_config_item['name']] = mb_connect(mb_config_item['type'], host=mb_config_item['host'], port=mb_config_item['port'], mb_timeout=mb_config_item['timeout_seconds'])

            if round(millis()*1000) - current_log_timers[mb_config_item['name']] >= int(mb_config_item['current_log']['scan_interval_ms']) and client[mb_config_item['name']].connected == True and isRunning == True:

                """ Reset timer, waiting for the next cycle """
                current_log_timers[mb_config_item['name']] = round(millis()*1000)

                if mb_config_item['name'] not in last_dtu:
                    last_dtu[mb_config_item['name']] = 0

                current_log_group_ids = get_log_group_ids(mb_config_item['current_log']['group_ids'])
                current_log_items = get_evc_log(current_log_group_ids)

                all_register_items = current_log_items['items']

                for current_slave_id in all_register_items:
                    register_items = all_register_items[current_slave_id]

                    if mb_config_item['current_log']['debug'] is True:
                        print(register_items)

                    if len(register_items) > 0:
                        if mb_config_item['name'] not in current_device_id:
                            q_get_deviceID = "SELECT id FROM %s_devices WHERE mbmaster_name = ? AND slaveID = ? LIMIT 1" % db_config_detail[0]['tbl_prefix']
                            db_cur.execute(q_get_deviceID, (mb_config_item['name'], current_slave_id))

                            if db_cur.rowcount == 0:
                                db_cur.execute("INSERT INTO %s_devices (`mbmaster_name`, `slaveID`) VALUES (?, ?)" % db_config_detail[0]['tbl_prefix'], (mb_config_item['name'], current_slave_id))
                                continue

                            rows_device_id = db_cur.fetchone()

                            current_device_id[mb_config_item['name']] = rows_device_id[0]
                            q_get_current = "SELECT id FROM %s_current_log WHERE deviceID = ?" % db_config_detail[0]['tbl_prefix']
                            db_cur.execute(q_get_current, (current_device_id[mb_config_item['name']],))

                            if db_cur.rowcount == 0:
                                send_current_log(current_device_id[mb_config_item['name']], insert_log=True)

                        send_current_log(current_device_id[mb_config_item['name']], register_items)

                        if evctime_reg['name'] in register_items:
                            last_dtu_str = dt_utc_to_current(last_dtu[mb_config_item['name']], evctime_reg['data_type'])
                            current_dtu_str = dt_utc_to_current(register_items[evctime_reg['name']], evctime_reg['data_type'])

                            """ Get hourly log when EVC hour has changed """
                            if (last_dtu_str.hour != current_dtu_str.hour or archive_log_failed['hourly_log'] == True) and archive_log_enabled['hourly_log'] == True:
                                if send_archive_log(current_device_id[mb_config_item['name']], mb_config_item['hourly_log']['group_ids'], 'hourly_log')['status'] != 1:
                                    archive_log_failed['hourly_log'] = True
                                else:
                                    archive_log_failed['hourly_log'] = False if archive_log_failed['hourly_log'] == True else archive_log_failed['hourly_log']

                            if mb_config_item['daily_log']['day_start_hour'] > 0:
                                last_dtu_str -= timedelta(hours=mb_config_item['daily_log']['day_start_hour'])
                                current_dtu_str -= timedelta(hours=mb_config_item['daily_log']['day_start_hour'])

                            """ Get daily log when EVC day has changed """
                            if (last_dtu_str.day != current_dtu_str.day or archive_log_failed['daily_log'] == True) and archive_log_enabled['daily_log'] == True:
                                if send_archive_log(current_device_id[mb_config_item['name']], mb_config_item['daily_log']['group_ids'], 'daily_log')['status'] != 1:
                                    archive_log_failed['daily_log'] = True
                                else:
                                    archive_log_failed['daily_log'] = False if archive_log_failed['daily_log'] == True else archive_log_failed['daily_log']

                            """ Get monthly log when EVC month has changed """
                            if (last_dtu_str.month != current_dtu_str.month or archive_log_failed['monthly_log'] == True) and archive_log_enabled['monthly_log'] == True:
                                if send_archive_log(current_device_id[mb_config_item['name']], mb_config_item['monthly_log']['group_ids'], 'monthly_log')['status'] != 1:
                                    archive_log_failed['monthly_log'] = True
                                else:
                                    archive_log_failed['monthly_log'] = False if archive_log_failed['monthly_log'] == True else archive_log_failed['monthly_log']

                            if mb_config_item['daily_log']['day_start_hour'] > 0:
                                last_dtu_str += timedelta(hours=mb_config_item['daily_log']['day_start_hour'])
                                current_dtu_str += timedelta(hours=mb_config_item['daily_log']['day_start_hour'])

                            """ START - Check Request Log """
                            q_check_request_log = "SELECT id, archiveLog, logRetention FROM %s_request_log WHERE deviceID = ? AND requestStatus = 0 AND archiveLog >= 0 AND archiveLog < ?" % db_config_detail[0]['tbl_prefix']
                            db_cur.execute(q_check_request_log, (current_device_id[mb_config_item['name']], len(archive_log_list)))

                            if db_cur.rowcount > 0:
                                rows_request_log = db_cur.fetchall()
                                for row_request_log in rows_request_log:
                                    if row_request_log[2] <= mb_config_item[archive_log_list[row_request_log[1]]]['max_retention'] and archive_log_enabled[archive_log_list[row_request_log[1]]] == True:
                                        if len(send_archive_log(current_device_id[mb_config_item['name']], mb_config_item[archive_log_list[row_request_log[1]]]['group_ids'], archive_log_list[row_request_log[1]], row_request_log[2])['items']) > 0:
                                            q_request_log_status = 1
                                        else:
                                            q_request_log_status = 2
                                    else:
                                        q_request_log_status = 2

                                    q_update_request_log = "UPDATE %s_request_log SET requestStatus = ? WHERE id = ?" % db_config_detail[0]['tbl_prefix']
                                    db_cur.execute(q_update_request_log, (q_request_log_status, row_request_log[0]))
                            """ END - Check Request Log """

                            last_dtu[mb_config_item['name']] = register_items[evctime_reg['name']]
        try:
            sleep(0.1)
        except KeyboardInterrupt:
            app_exit()

    modbus_close()
    db_close()