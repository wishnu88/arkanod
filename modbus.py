#!/usr/bin/env python3

import yaml
import mariadb
import sys
import logging
from signal import (signal as os_signal, SIGTERM, SIGINT)
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.transaction import (ModbusRtuFramer, ModbusAsciiFramer, ModbusSocketFramer)
from time import (sleep, time as millis)
from datetime import (datetime, timezone)

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
    'int16',
    'int32',
    'int64',
    'string',
    'uint16',
    'uint32',
    'uint64',
    'dt1'
]

archive_log_list = [
    'hourly',
    'daily',
    'monthly'
]

def app_exit(exitVal: int = 0):
   logging.info("Exiting...") if logging.getLogger().hasHandlers() else print("Exiting...")

   if 'client' in globals() and client.connected:
      logging.info("Disconnecting from Modbus devices...")
      client.close()

   sys.exit(exitVal)

def convert_registers(registers, swap_type):
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

    if data_type == 'float16':
        decoded = results.decode_16bit_float()
    elif data_type == 'float32':
        decoded = results.decode_32bit_float()
    elif data_type == 'float64':
        decoded = results.decode_64bit_float()
    elif data_type == 'int16':
        decoded = results.decode_16bit_int()
    elif data_type == 'int32':
        decoded = results.decode_32bit_int()
    elif data_type == 'int64':
        decoded = results.decode_64bit_int()
    elif data_type == 'string':
        decoded = results.decode_string()
    elif data_type == 'uint16':
        decoded = results.decode_16bit_uint()
    elif data_type == 'uint32':
        decoded = results.decode_32bit_uint()
    elif data_type == 'uint64':
        decoded = results.decode_64bit_uint()
    elif data_type == 'dt1':
        decoded = results.decode_32bit_uint()
    else:
        raise Exception('Invalid Modbus register data_type option. Supported options are: %s' % data_type_list)

    return decoded

def mb_connect(type, port: str, host: str = None, mb_timeout: int = None):
    if type in ['rtuovertcp','tcp']:        
        try:
            print("Connecting to %s port %s..." % (host, port))
            if 'ModbusTcpClient' not in sys.modules:
                from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(host=host, port=int(port), framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            print("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            print('Unable to establish connection to %s port %s.' % (host, port))
    elif type == 'rtu':        
        try:
            print("Connecting to port %s..." % port)
            if 'ModbusSerialClient' not in sys.modules:
                from pymodbus.client import ModbusSerialClient
            client = ModbusSerialClient(port=port, framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            print("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            print('Unable to establish connection to %s port %s.' % (host, port))

def get_log_group_ids(register_group_ids) -> list:
    register_group_address = []
    for register_group in mb_config_item['register_group']:
        """Skip group_id not included in group_ids"""
        if register_group['group_id'] not in register_group_ids:
            continue
        register_group_address.append(register_group)

    return register_group_address

def get_evc_log(register_groups) -> dict:
    global client
    
    register_group_address = {}
    register_items = {}
    for register_group in register_groups:
        # """Define Data Type as uint16 if not specified in config."""
        # if 'type' not in register_group:
        #     register_group['type'] = 'uint16'

        register_gap = 0 if 'gap' not in register_group else register_group['gap']

        if register_group['type'] not in register_type_list:
            raise Exception('Invalid Modbus register type option for register group %s. Supported options are: %s' % (register_group['group_id'], register_type_list))
        
        current_slave_id = int(register_group['slave'])
        """ Modbus read delay """
        sleep((mb_config_item['wait_milliseconds'] / 1000))
        if register_group['type'] == "input":
            try:
                result = client.read_input_registers(int(register_group['address']) + register_gap, register_group['count'], slave=current_slave_id)
            except:
                print('Unable to establish connection to %s port %s. Retrying...' % (mb_config_item['host'], mb_config_item['port']))
                continue
        elif register_group['type'] == "holding":
            try:
                result = client.read_holding_registers(int(register_group['address']) + register_gap, register_group['count'], slave=current_slave_id)
            except:
                print('Unable to establish connection to %s port %s. Retrying...' % (mb_config_item['host'], mb_config_item['port']))
                continue
        if hasattr(result, 'registers') == False:
            print('Unable to poll Modbus device on %s port %s with slave ID %s. Retrying...' % (mb_config_item['host'], mb_config_item['port'], register_group['slave']))
            if client.connected == False:
                client = mb_connect(mb_config_item['type'], host=mb_config_item['host'], port=mb_config_item['port'], mb_timeout=mb_config_item['timeout_seconds'])
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
            if register_conversion['group_id'] != register_group['group_id']:
                continue

            if register_conversion['swap'] not in swap_type_list:
                raise Exception('Invalid byte swap option for. Supported options are: %s' % swap_type_list)
        
            current_registers = []
            register_value_precision = 0 if 'precision' not in register_conversion else register_conversion['precision']

            for register_i in range(int(register_conversion['registers'][0]) + register_gap, int(register_conversion['registers'][1]) + register_gap + 1):
                try:
                    current_registers.append(register_group_address[register_conversion['group_id']][register_i])
                except:
                    continue
            
            if len(current_registers) > 0:
                register_value = decode_results(convert_registers(current_registers, register_conversion['swap']), register_conversion['data_type'])
                register_items[register_conversion['name']] = round(register_value, register_value_precision) if register_value_precision != "none" else register_value
    
    return {'items': register_items, 'slaveID': current_slave_id}

def send_archive_log(deviceID: int, group_ids, kind: str, retention: int = 0):
    if kind in archive_log_list:
        archive_log_group_ids = get_log_group_ids(group_ids)
        
        all_archive_log_items = []
        for n_iter in range(0, retention + 1):
            if retention > 0:
                for group_id_index in range(0, len(archive_log_group_ids)):
                    archive_log_group_ids[group_id_index]['gap'] = n_iter * archive_log_group_ids[group_id_index]['count']

            archive_log_items = get_evc_log(archive_log_group_ids)['items']

            archive_tbl = "ptzbox5_hourly_log" if kind == "hourly" else "ptzbox5_daily_log" if kind == "daily" else "ptzbox5_monthly_log"
            archive_prefix = "h_" if kind == "hourly" else "d_" if kind == "daily" else "m_"

            try:
                q_insert_archive = "INSERT IGNORE INTO " + archive_tbl + " (deviceID, Vb, Vm, FlowTm, p1Avg, p1Min, p1Max, tAvg, tMin, tMax, QmAvg, QmMin, QmMax, QbAvg, QbMin, QbMax, tambAvg, dVbSum, dVmSum, BattLvl, DTStamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
                items = (
                    deviceID,
                    archive_log_items[archive_prefix + 'Vb'],
                    archive_log_items[archive_prefix + 'Vm'],
                    archive_log_items[archive_prefix + 'FlowTm'],
                    archive_log_items[archive_prefix + 'p1Avg'],
                    archive_log_items[archive_prefix + 'p1Min'],
                    archive_log_items[archive_prefix + 'p1Max'],
                    archive_log_items[archive_prefix + 'tAvg'],
                    archive_log_items[archive_prefix + 'tMin'],
                    archive_log_items[archive_prefix + 'tMax'],
                    archive_log_items[archive_prefix + 'QmAvg'],
                    archive_log_items[archive_prefix + 'QmMin'],
                    archive_log_items[archive_prefix + 'QmMax'],
                    archive_log_items[archive_prefix + 'QbAvg'],
                    archive_log_items[archive_prefix + 'QbMin'],
                    archive_log_items[archive_prefix + 'QbMax'],
                    archive_log_items[archive_prefix + 'tambAvg'],
                    archive_log_items[archive_prefix + 'dVbSum'],
                    archive_log_items[archive_prefix + 'dVmSum'],
                    archive_log_items[archive_prefix + 'BattLvl'],
                    dt_utc_to_current(archive_log_items[archive_prefix + 'DTStamp']),
                    )
                
                db_cur.execute(q_insert_archive, items)
                if db_cur.rowcount > 0:
                    all_archive_log_items.append(archive_log_items)
            except Exception as e:
                print(archive_log_items)
        
        return all_archive_log_items

def send_current_log(deviceID: int, items: tuple = None, insert_log = False) -> bool:
    if insert_log == True:
        try:
            q_insert_current = "INSERT INTO ptzbox5_current_log (deviceID) VALUES (?)"
            db_cur.execute(q_insert_current, (deviceID,))
        except:
            return False
    else:
        try:
            """Insert deviceID to the last element of items for WHERE clause"""
            items = items + (deviceID,)
            q_update_current = "UPDATE ptzbox5_current_log SET dtu = ?, Vb = ?, Vm = ?, p1 = ?, t = ?, Qm = ?, Qb = ?, EPwrSActive = ?, EPwrSCheck = ?, ETL = ?, BattLvl = ? WHERE deviceID = ?"
            db_cur.execute(q_update_current, items)
        except:
            return False
    return True

def dt_utc_to_current(timestamp: int) -> datetime:
    return datetime.strptime(str(datetime.fromtimestamp(timestamp, timezone.utc)), '%Y-%m-%d %H:%M:%S%z')

def signal_term_handler(signal, frame):
   app_exit()

os_signal(SIGTERM, signal_term_handler)
os_signal(SIGINT, signal_term_handler)

with open('modbus.yaml', 'r') as mb_config:
    mb_config_detail = yaml.safe_load(mb_config)
    mb_config.close()

with open('db.yaml', 'r') as db_config:
    db_config_detail = yaml.safe_load(db_config)
    if 'db_port' not in db_config_detail[0]:
        db_config_detail[0]['db_port'] = 3306
    db_config.close()

try:
    db_conn = mariadb.connect(
        host=db_config_detail[0]['db_host'],
        port=db_config_detail[0]['db_port'],
        user=db_config_detail[0]['db_username'],
        password=db_config_detail[0]['db_password'],
        database=db_config_detail[0]['db_name'],
        autocommit=True,
        reconnect=True)

    # Instantiate MariaDB Cursor
    db_cur = db_conn.cursor()
except mariadb.Error as e:
    print(f"Error connecting to the database: {e}")
    app_exit(1)

current_log_timers = {}
for mb_config_item in mb_config_detail:
    current_log_timers[mb_config_item['name']] = 0

while True:
    for mb_config_item in mb_config_detail:
        """Sanity check for Modbus Type config."""
        if mb_config_item['type'] not in modbus_type_list:
            raise Exception('Invalid Modbus type option. Supported options are: %s' % modbus_type_list)

        if 'client' not in vars() or ('client' in vars() and hasattr(client, 'connected') and client.connected == False):
            client = mb_connect(mb_config_item['type'], host=mb_config_item['host'], port=mb_config_item['port'], mb_timeout=mb_config_item['timeout_seconds'])

        if round(millis()*1000) - current_log_timers[mb_config_item['name']] >= int(mb_config_item['current_log']['scan_interval_ms']) and client.connected == True:
            """Reset timer, waiting for the next cycle"""
            current_log_timers[mb_config_item['name']] = round(millis()*1000)

            if 'last_dtu' not in vars():
                last_dtu = 0

            current_log_group_ids = get_log_group_ids(mb_config_item['current_log']['group_ids'])
            current_log_items = get_evc_log(current_log_group_ids)
            register_items = current_log_items['items']
            current_slave_id = current_log_items['slaveID']

            if 'current_slave_id' in vars() and len(register_items) > 0:
                if 'current_device_id' not in vars():
                    q_get_deviceID = "SELECT id FROM ptzbox5_devices WHERE mbmaster_name = ? AND slaveID = ? LIMIT 1"
                    db_cur.execute(q_get_deviceID, (mb_config_item['name'], current_slave_id))
                    rows_device_id = db_cur.fetchone()

                    current_device_id = rows_device_id[0]
                    q_get_current = "SELECT id FROM ptzbox5_current_log WHERE deviceID = ?"
                    db_cur.execute(q_get_current, (current_device_id,))

                    if db_cur.rowcount == 0:
                        send_current_log(current_device_id, insert_log=True)

                send_current_log(current_device_id, (dt_utc_to_current(register_items['dtu']),
                                                     register_items['Vb'],
                                                     register_items['Vm'],
                                                     register_items['p1'],
                                                     register_items['t'],
                                                     register_items['Qm'],
                                                     register_items['Qb'],
                                                     register_items['EPwrSActive'],
                                                     register_items['EPwrSCheck'],
                                                     register_items['ETL'],
                                                     register_items['BattLvl']))

                if 'dtu' in register_items:
                    last_dtu_str = dt_utc_to_current(last_dtu)
                    current_dtu_str = dt_utc_to_current(register_items['dtu'])

                    """Get hourly log when EVC hour has changed"""
                    if last_dtu_str.hour != current_dtu_str.hour:
                        send_archive_log(current_device_id, mb_config_item['hourly_log']['group_ids'], 'hourly')

                    """Get daily log when EVC day has changed"""
                    if last_dtu_str.day != current_dtu_str.day:
                        send_archive_log(current_device_id, mb_config_item['daily_log']['group_ids'], 'daily')

                    """Get monthly log when EVC month has changed"""
                    if last_dtu_str.month != current_dtu_str.month:
                        send_archive_log(current_device_id, mb_config_item['monthly_log']['group_ids'], 'monthly')

                    """ Check Request Log """
                    q_check_request_log = 'SELECT id, archiveLog, logRetention FROM ptzbox5_request_log WHERE deviceID = ? AND requestStatus = 0'
                    db_cur.execute(q_check_request_log, (current_device_id,))

                    if db_cur.rowcount > 0:
                        rows_request_log = db_cur.fetchall()
                        for row_request_log in rows_request_log:
                            if row_request_log[2] <= mb_config_item['monthly_log']['max_retention']:
                                if len(send_archive_log(current_device_id, mb_config_item[archive_log_list[row_request_log[1]] + '_log']['group_ids'], archive_log_list[row_request_log[1]], row_request_log[2])) > 0:
                                    q_update_request_log = 'UPDATE ptzbox5_request_log SET requestStatus = 1 WHERE id = ?'
                            else:
                                q_update_request_log = 'UPDATE ptzbox5_request_log SET requestStatus = 2 WHERE id = ?'

                            db_cur.execute(q_update_request_log, (row_request_log[0],))
                    last_dtu = register_items['dtu']
    try:
        sleep(0.1)
    except KeyboardInterrupt:
        app_exit()
