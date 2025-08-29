# -*- coding: utf-8 -*-
"""
Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address
MODBUS protocol.

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

The MODBUS DeviceRead class file.
"""
import threading
from struct import error as StructError
from time import (sleep, time as millis)
from datetime import timedelta, datetime
from MySQLdb import Error as DBError
from pymodbus import ModbusException

from danismod.funcs import print_log, dt_utc_to_current
from danismod.mb_funcs import mb_connect, mb_convert_registers, mb_close
from danismod.db_funcs import db_open, db_close
from .const import ARCHIVE_LOG_LIST, ARCHIVE_LOG_FAILED

class DeviceRead(threading.Thread):
    """
    A simple class extending a threading.Thread class for reading a MODBUS device.
    """

    def __init__(self, mb_config_item: dict, evctime_reg: dict, db_params: dict,
                 archive_log_enabled: dict):
        threading.Thread.__init__(self)
        self.db_conn_params = {
            'host': db_params['db_host'],
            'port': db_params['db_port'],
            'user': db_params['db_username'],
            'password': db_params['db_password'],
            'database': db_params['db_name'],
            'autocommit': True,
            # 'reconnect': True
        }
        self.tparams = {
            'stop_me': threading.Event(),
            'mb_client': None,
            'archive_log_enabled': archive_log_enabled
        }
        self.db_cur = None
        self.mb_config_item = mb_config_item
        self.db_tbl_prefix = db_params['tbl_prefix']
        self.evctime_reg = evctime_reg
        self.current_log_timer = 0

    def get_log_group_ids(self, register_group_ids: list) -> list:
        """
        Return list of every group_id MODBUS register address referenced in the configured EVC log.

        Mandatory keyword argument:
        register_group_ids: list; group_id list configured for the corresponding EVC log.
        """

        register_group_address = []

        for register_group in self.mb_config_item['register_group']:

            # Skip group_id not included in group_ids.
            if register_group['group_id'] not in register_group_ids:
                continue

            register_group_address.append(register_group)

        return register_group_address

    def get_evc_log(self, register_groups: list, slave_id: int = None) -> dict:
        """
        Get log items value fron EVC and return the dict of it.

        Mandatory keyword argument:
        register_groups: list; MODBUS register address groups configured for the corresponding EVC
                         log.

        Optional keyword argument:
        slave_id: int; specify device ID of configured EVC. Must be specified when retrieving the
                  EVC archive log.
        """
        register_group_address = {}
        register_items = {}
        register_slave_ids = {}
        read_answered = 0

        for register_group in register_groups:

            current_slave_id = int(register_group['slave'])

            # Variable initialization for storing register_items per slave_id.
            if current_slave_id not in register_items:
                register_items[current_slave_id] = {}

            result = None

            if slave_id is not None and slave_id != current_slave_id:
                continue
            register_gap = 0 if 'gap' not in register_group else register_group['gap']

            # Modbus read delay.
            sleep((self.mb_config_item['wait_milliseconds'] / 1000))

            try:
                # Read from the EVC using MODBUS protocol.
                if register_group['type'] == "input":
                    result = self.tparams['mb_client'].read_input_registers(
                        address=int(register_group['address']) + register_gap,
                        count=register_group['count'],
                        device_id=current_slave_id)
                elif register_group['type'] == "holding":
                    result = self.tparams['mb_client'].read_holding_registers(
                        address=int(register_group['address']) + register_gap,
                        count=register_group['count'],
                        device_id=current_slave_id)
            except (ModbusException, StructError, OSError) as e:
                # Throw an error when the EVC didn't response to MODBUS poll.
                print_log(f"[{self.name}] Unable to poll Modbus device register address "
                          f"{register_group['address']} count {register_group['count']} on "
                          f"{self.tparams['mb_client']} with slave ID {register_group['slave']}: "
                          f"{e}. Moving on...", 'error')
                continue

            # Throw an error when no MODBUS register value is received from the EVC, although it
            # responds to the MODBUS poll.
            if not hasattr(result, 'registers') or result.isError():
                print_log(f"[{self.name}] Broken response from Modbus device register address "
                          f"{register_group['address']} count {register_group['count']} on "
                          f"{self.tparams['mb_client']} with slave ID {register_group['slave']}: "
                          f"{e}. Moving on...", 'error')
                sleep(self.mb_config_item['timeout_seconds'])
                if self.tparams['mb_client'].connected is False:
                    print_log(f"[{self.name}] Disconnected from {self.tparams['mb_client']}.",
                              'error')
                    self.tparams['mb_client'] = mb_connect(self.mb_config_item['type'],
                                                host=self.mb_config_item['host'],
                                                port=self.mb_config_item['port'],
                                                mb_timeout=self.mb_config_item['timeout_seconds'])
                    self.current_log_timer = 0
                continue

            read_answered += 1

            # Map received MODBUS register value to the corresponding group_id address and count.
            if len(result.registers) == register_group['count']:
                register_addr_map = register_group['address'] + register_gap
                register_group_values = {}
                for result_map in result.registers:
                    register_group_values[register_addr_map] = result_map
                    register_addr_map = register_addr_map + 1
            else:
                continue

            register_group_address[register_group['group_id']] = register_group_values

            # Convert MODBUS register value to the configured data type items.
            for register_conversion in self.mb_config_item['register_conversion']:
                group_exists = 0
                for group_id in register_conversion['group_ids']:
                    if group_id == register_group['group_id']:
                        group_exists = 1
                        break

                if group_exists == 0:
                    continue

                current_registers = []
                register_value_precision = (0 if 'precision' not in register_conversion
                                            else register_conversion['precision'])

                for register_i in range(
                    int(register_conversion['registers'][0]) + register_gap,
                    int(register_conversion['registers'][1]) + register_gap + 1):
                    try:
                        current_registers.append(
                            register_group_address[register_group['group_id']][register_i])
                    except IndexError:
                        continue

                if len(current_registers) > 0:
                    register_value = mb_convert_registers(
                        registers = current_registers,
                        data_type = register_conversion['data_type'],
                        swap_type = (register_conversion['swap'] if 'swap' in register_conversion
                                     else None))
                    register_items[current_slave_id][register_conversion['name']] = (round(
                        register_value,
                        register_value_precision) if register_value_precision != "none"
                        else register_value)
                    register_slave_ids[register_conversion['name']] = current_slave_id

        # Only disconnect when slave_id is not set and no answer is received so that the
        # archive_log operation will not break the multi-slave MODBUS connection.
        if slave_id is None and read_answered == 0:
            mb_close(self.tparams['mb_client'])

        # Return the dict of already converted MODBUS registers data type along with the mapped
        # device ID.
        return {'items': register_items if slave_id is None else register_items[slave_id],
                'slaveIDs': register_slave_ids}

    def send_current_log(self, device_id: int, items: dict = None,
                         insert_log: bool = False) -> bool:
        """
        Send the received EVC current/instantaneous log values to the database (or STDOUT for
        debugging purposes).

        Mandatory keyword argument:
        device_id: int; Device ID retrieved from the database for each EVC device.

        Optional keyword arguments:
        items: dict; The dict of item list of the EVC current log to be retrieved. Default: None.
        insert_log: bool; Whether to insert a new record for a newly connected EVC device or not.
                    Default: False.
        """
        if insert_log is True:
            try:
                q_insert_current = "INSERT INTO " + self.db_tbl_prefix + "_current_log (deviceID)" \
                    " VALUES (%s)"
                self.db_cur.execute(q_insert_current, (device_id,))
            except (KeyError, DBError) as e:
                print_log(f"[{self.name}] send_current_log() insert: {e}", 'error')
                return False
        else:
            try:
                # Create the current log query template using dictionary.
                q_update_current_log = "UPDATE " + self.db_tbl_prefix + "_current_log SET "
                q_update_items = []
                for item_name in items:
                    q_update_items.append(f"{item_name} = %({item_name})s")
                q_update_current_log += ", ".join(q_update_items) + " WHERE deviceID = " + \
                    str(device_id)
                self.db_cur.execute(q_update_current_log, items)
            except (KeyError, DBError) as e:
                print_log(f"[{self.name}] send_current_log() update: {e}", 'error')
                return False
        return True

    def send_archive_log(self, device_id: int, kind: str, slave_id: int, retention: int=0) -> dict:
        """
        Send the received EVC archive log values to the database (or STDOUT for debugging purposes).

        Mandatory keyword arguments:
        device_id: int; Device ID retrieved from the database for each EVC device.
        groups_ids: list; List of the configured group_id for the corresponding EVC archive log.
        kind: str; Archive log kind (usually one of this: hourly, daily, monthly).

        Optional keyword arguments:
        retention: int; The count of retention of the backlog EVC archive log from the newest to
                   the oldest data. Default: 0.
        slave_id: int; The EVC device MODBUS slave ID. Default: 1.
        """
        success_status = 0

        if kind not in ARCHIVE_LOG_LIST:
            return {'items': None, 'status': success_status}

        # Get the configured group_id for the corresponding EVC archive log.
        archive_log_group_ids = self.get_log_group_ids(self.mb_config_item[kind]['group_ids'])

        all_archive_log_items = []

        # Iterate once if no/zero retention is specified.
        for n_iter in range(0 if retention == 0 else 1, retention + 1):
            if retention > 0:
                for group_id_index in enumerate(archive_log_group_ids):
                    archive_log_group_ids[group_id_index[0]]['gap'] = n_iter * \
                        archive_log_group_ids[group_id_index[0]]['count']

            # MODBUS poll the EVC device.
            archive_log_items = self.get_evc_log(archive_log_group_ids, slave_id)['items']

            # Send the received MODBUS responses to STDOUT for debugging purposes only.
            if self.mb_config_item[kind]['debug'] is True:
                print_log(f"[{self.name}] {archive_log_items}")

            if retention > 0:
                for group_id_index in enumerate(archive_log_group_ids):
                    del archive_log_group_ids[group_id_index[0]]['gap']

            try:
                # Insert the received MODBUS responses (EVC archive log items value) into the
                # database; otherwise, throw an error.
                q_insert_archive = "INSERT IGNORE INTO " + self.db_tbl_prefix + '_' + kind + \
                    " (deviceID, " + ', '.join(archive_log_items) + ") VALUES (" + \
                        str(device_id) + ", %(" + ")s, %(".join(list(archive_log_items)) + ")s)"
                self.db_cur.execute(q_insert_archive, archive_log_items)
                if self.db_cur.rowcount > 0:
                    all_archive_log_items.append(archive_log_items)
            except (DBError, KeyError) as e:
                print_log(f"[{self.name}] send_archive_log(): {e} during {kind} operation for "
                            f"device_id {device_id}.", 'error')
                if retention == 0:
                    success_status = 2
            else:
                if retention == 0:
                    success_status = 1

        # Return the EVC archive log items value along with the general success status.
        return {'items': all_archive_log_items, 'status': success_status}

    def device_reconnect(self, modbus_connected: bool) -> bool:
        """
        Docstring test
        """
        if self.tparams['mb_client'] is not None and modbus_connected is True:
            print_log(f"[{self.name}] Disconnected from {self.tparams['mb_client']}.",
                        'error')
            modbus_connected = False

        self.tparams['mb_client'] = mb_connect(self.mb_config_item['type'],
                                    host=self.mb_config_item['host'],
                                    port=self.mb_config_item['port'],
                                    mb_timeout=self.mb_config_item['timeout_seconds'])

        if self.tparams['mb_client'].connected is True:
            self.current_log_timer = 0
            modbus_connected = True
        else:
            # Reset timer, waiting for the next cycle.
            self.current_log_timer = round(millis()*1000)

        return modbus_connected

    def run(self):
        # Open database and then map the connection and the cursor for later use.
        [db_conn, self.db_cur] = db_open(self.db_conn_params)

        current_device_id = {}
        last_dtu_dev = {}
        archive_log_failed = {}
        modbus_connected = False

        # Define EVC time source.
        if self.evctime_reg['name'] == self.evctime_reg['data_type'] == 'dbserver':
            dtu_source = 'dbserver'
        else:
            dtu_source = 'evc'

        while not self.tparams['stop_me'].is_set():
            # Pause between MODBUS device connection attempts if it fails.
            scan_interval_ms = int(self.mb_config_item['current_log']['scan_interval_ms'])
            mb_conditions = [
                self.tparams['mb_client'] is None,                                  # 0
                self.tparams['mb_client'] is not None,                              # 1
                hasattr(self.tparams['mb_client'], 'connected'),                    # 2
                round(millis()*1000) - self.current_log_timer >= scan_interval_ms   # 3
            ]
            mb_not_connected = mb_conditions[1] and mb_conditions[2]
            mb_not_connected = mb_not_connected and self.tparams['mb_client'].connected is False

            if ((mb_conditions[0] or mb_not_connected) and mb_conditions[3]):
                modbus_connected = self.device_reconnect(modbus_connected)

            # Poll the EVC device when the current log scan time deadline is met.
            if not (mb_conditions[3] and not mb_not_connected and self.is_alive()):
                sleep(0.1)
                continue

            try:
                db_conn.ping()
            except (KeyError, DBError) as e:
                print_log(f"[{self.name}] Database connection error detected: {e}. "
                            "Reconnecting...", 'error')
                [db_conn, self.db_cur] = db_open(self.db_conn_params)

            # Reset timer, waiting for the next cycle.
            self.current_log_timer = round(millis()*1000)

            current_log_group_ids = self.get_log_group_ids(
                self.mb_config_item['current_log']['group_ids'])

            # MODBUS poll to the EVC device
            current_log_items = self.get_evc_log(current_log_group_ids)
            all_register_items = current_log_items['items']

            for current_slave_id in all_register_items:
                register_items = all_register_items[current_slave_id]

                if current_slave_id not in last_dtu_dev:
                    last_dtu_dev[current_slave_id] = 0 if dtu_source == 'evc' \
                        else datetime(1970, 1, 1, 0, 0, 0)
                    archive_log_failed[current_slave_id] = ARCHIVE_LOG_FAILED.copy()

                last_dtu = last_dtu_dev[current_slave_id]

                # Pull items count for current slave_id.
                items_count = 0
                for register_conversion in self.mb_config_item['register_conversion']:
                    for current_log_item in current_log_group_ids:
                        if current_log_item['group_id'] in register_conversion['group_ids']:
                            items_count += 1
                            break

                # Continue to the next slave_id if the received items count mismatch happens.
                if len(register_items) != items_count:
                    print_log(f"[{self.name}] Items count mismatch received for slave ID "
                              f"{current_slave_id}. Skipping.", 'error')
                    continue

                if self.mb_config_item['current_log']['debug'] is True:
                    print(f"[{self.name}] {register_items}")

                if current_slave_id not in current_device_id:
                    q_get_device_id = "SELECT id FROM " + self.db_tbl_prefix + "_devices " \
                        "WHERE mbmaster_name = %s AND slaveID = %s LIMIT 1"
                    self.db_cur.execute(q_get_device_id, (self.mb_config_item['name'],
                                                            current_slave_id))

                    if self.db_cur.rowcount > 0:
                        rows_device_id = self.db_cur.fetchone()
                        current_device_id[current_slave_id] = rows_device_id[0]
                    else:
                        self.db_cur.execute("INSERT INTO " + self.db_tbl_prefix + \
                                            "_devices (`mbmaster_name`, `slaveID`) " \
                                                "VALUES (%s, %s)",
                                            (self.mb_config_item['name'], current_slave_id))
                        current_device_id[current_slave_id] = self.db_cur.lastrowid

                    q_get_current = "SELECT id FROM " + self.db_tbl_prefix + "_current_log " \
                        "WHERE deviceID = %s"
                    self.db_cur.execute(q_get_current, (current_device_id[current_slave_id],))

                    if self.db_cur.rowcount == 0:
                        self.send_current_log(current_device_id[current_slave_id], insert_log=True)

                self.send_current_log(current_device_id[current_slave_id], register_items)

                if dtu_source == 'dbserver':
                    last_dtu_str = last_dtu
                    current_dtu_str = datetime.now()
                else:
                    last_dtu_str = dt_utc_to_current(last_dtu, self.evctime_reg['data_type'])
                    current_dtu_str = dt_utc_to_current(register_items[self.evctime_reg['name']],
                                                        self.evctime_reg['data_type'])

                # Get hourly log when EVC hour has changed.
                dtu_conditions = [
                    last_dtu_str.hour != current_dtu_str.hour,
                    archive_log_failed[current_slave_id]['hourly_log'] is True,
                    self.tparams['archive_log_enabled']['hourly_log'] is True
                ]
                if (dtu_conditions[0] or dtu_conditions[1]) and dtu_conditions[2]:
                    if (self.send_archive_log(current_device_id[current_slave_id], 'hourly_log',
                                              current_slave_id)['status'] != 1):
                        archive_log_failed[current_slave_id]['hourly_log'] = True
                    elif archive_log_failed[current_slave_id]['hourly_log'] is True:
                        archive_log_failed[current_slave_id]['hourly_log'] = False

                # Substract the last current time of the EVC device by the configured
                # day_start_hour, only if day_start_hour > 0, for the relativity effect
                # of the daily log and the monthly log.
                if self.tparams['archive_log_enabled']['daily_log'] is True and \
                    self.mb_config_item['daily_log']['day_start_hour'] > 0:
                    last_dtu_str -= timedelta(
                        hours=self.mb_config_item['daily_log']['day_start_hour'])
                    current_dtu_str -= timedelta(
                        hours=self.mb_config_item['daily_log']['day_start_hour'])

                # Get daily log when EVC day has changed.
                dtu_conditions = [
                    last_dtu_str.day != current_dtu_str.day,
                    archive_log_failed[current_slave_id]['daily_log'] is True,
                    self.tparams['archive_log_enabled']['daily_log'] is True
                ]
                if (dtu_conditions[0] or dtu_conditions[1]) and dtu_conditions[2]:
                    if self.send_archive_log(current_device_id[current_slave_id], 'daily_log',
                                             current_slave_id)['status'] != 1:
                        archive_log_failed[current_slave_id]['daily_log'] = True
                    elif archive_log_failed[current_slave_id]['daily_log'] is True:
                        archive_log_failed[current_slave_id]['daily_log'] = False

                # Get monthly log when EVC month has changed.
                dtu_conditions = [
                    last_dtu_str.month != current_dtu_str.month,
                    archive_log_failed[current_slave_id]['monthly_log'] is True,
                    self.tparams['archive_log_enabled']['monthly_log'] is True
                ]
                if (dtu_conditions[0] or dtu_conditions[1]) and dtu_conditions[2]:
                    if self.send_archive_log(current_device_id[current_slave_id], 'monthly_log',
                                             current_slave_id)['status'] != 1:
                        archive_log_failed[current_slave_id]['monthly_log'] = True
                    elif archive_log_failed[current_slave_id]['monthly_log'] is True:
                        archive_log_failed[current_slave_id]['monthly_log'] = False

                del dtu_conditions
                # Add the last current time of the EVC device by the configured
                # day_start_hour, only if day_start_hour > 0, to reverse the relativity
                # effect above.
                if self.tparams['archive_log_enabled']['daily_log'] is True and \
                    self.mb_config_item['daily_log']['day_start_hour'] > 0:
                    last_dtu_str += timedelta(
                        hours=self.mb_config_item['daily_log']['day_start_hour'])
                    current_dtu_str += timedelta(
                        hours=self.mb_config_item['daily_log']['day_start_hour'])

                # START - Check Request Log.
                q_check_request_log = "SELECT id, archiveLog, logRetention FROM " + \
                    self.db_tbl_prefix + "_request_log WHERE deviceID = %s AND " \
                        "requestStatus = 0 AND archiveLog >= 0 AND archiveLog < %s"
                self.db_cur.execute(q_check_request_log, (current_device_id[current_slave_id],
                                                            len(ARCHIVE_LOG_LIST)))

                if self.db_cur.rowcount > 0:
                    rows_request_log = self.db_cur.fetchall()
                    for row_request_log in rows_request_log:
                        if row_request_log[2] <= self.mb_config_item[ARCHIVE_LOG_LIST[row_request_log[1]]]['max_retention'] and self.tparams['archive_log_enabled'][ARCHIVE_LOG_LIST[row_request_log[1]]] is True:
                            q_request_log_status = 1 if len(self.send_archive_log(current_device_id[current_slave_id], ARCHIVE_LOG_LIST[row_request_log[1]], current_slave_id, retention = row_request_log[2])['items']) > 0 else 2
                        else:
                            q_request_log_status = 2

                        q_update_request_log = "UPDATE " + self.db_tbl_prefix + "_request_log " \
                            "SET requestStatus = %s WHERE id = %s"
                        self.db_cur.execute(q_update_request_log, (q_request_log_status,
                        row_request_log[0]))
                # END - Check Request Log.

                # Time mark for the last EVC current log MODBUS poll.
                if dtu_source == 'evc':
                    last_dtu = register_items[self.evctime_reg['name']]
                else:
                    last_dtu = datetime.now()

                last_dtu_dev[current_slave_id] = last_dtu

        if (self.tparams['mb_client'] is not None and
            hasattr(self.tparams['mb_client'], 'connected') and
            self.tparams['mb_client'].connected is True):
            mb_close(self.tparams['mb_client'])

        db_close(db_conn)

    def shutdown(self):
        """
        A simple function to shutdown a thread.
        """
        self.tparams['stop_me'].set()
