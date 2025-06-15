import threading
from MySQLdb import OperationalError as DBOperationalError
from time import (sleep, time as millis)
from datetime import timedelta

from danismod.funcs import printLog, dt_utc_to_current
from danismod.mb_funcs import *
from danismod.db_funcs import db_open, db_close
from .const import ARCHIVE_LOG_LIST, ARCHIVE_LOG_ENABLED, ARCHIVE_LOG_FAILED

class device_read(threading.Thread):

    def __init__(self, mb_config_item: dict, evctime_reg: dict, db_params: dict):
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
        self.stop_me = threading.Event()
        self.db_cur = None
        self.mb_client = None
        self.mb_config_item = mb_config_item
        self.db_tbl_prefix = db_params['tbl_prefix']
        self.evctime_reg = evctime_reg
        self.archive_log_failed = ARCHIVE_LOG_FAILED.copy()
        self.current_log_timer = 0
        self.thread_id = threading.get_native_id()

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
        register_groups: list; MODBUS register address groups configured for the corresponding EVC log.

        Optional keyword argument:
        slave_id: int; specify device ID of configured EVC. Must be specified when retrieving the EVC archive log.
        """       
        register_group_address = {}
        register_items = {}
        register_slave_ids = {}
        error_msg = None

        for register_group in register_groups:
            
            current_slave_id = int(register_group['slave'])
            register_items[current_slave_id] = {}
            if slave_id is not None and slave_id != current_slave_id:
                continue
            register_gap = 0 if 'gap' not in register_group else register_group['gap']

            # Modbus read delay.
            sleep((self.mb_config_item['wait_milliseconds'] / 1000))

            try:
                # Read from the EVC using MODBUS protocol.
                if register_group['type'] == "input":
                    result = self.mb_client.read_input_registers(address=int(register_group['address']) + register_gap, count=register_group['count'], slave=current_slave_id)
                elif register_group['type'] == "holding":
                    result = self.mb_client.read_holding_registers(address=int(register_group['address']) + register_gap, count=register_group['count'], slave=current_slave_id)
            except Exception as e:
                # Throw an error when the EVC didn't response to MODBUS poll.
                printLog('[%s] Unable to poll Modbus device on %s port %s with slave ID %s: %s. Moving on...' % (self.name, self.mb_config_item['host'] if 'host' in self.mb_config_item else 'local', self.mb_config_item['port'], register_group['slave'], e), 'error')
                sleep(self.mb_config_item['timeout_seconds'])
                continue

            # Throw an error when no MODBUS register value is received from the EVC, although it responds to the MODBUS poll.
            if hasattr(result, 'registers') == False:
                printLog('[%s] Unexpected response from Modbus device on %s port %s with slave ID %s.' % (self.name, self.mb_config_item['host'] if 'host' in self.mb_config_item else 'local', self.mb_config_item['port'], register_group['slave']), 'error')
                sleep(self.mb_config_item['timeout_seconds'])
                if self.mb_client.connected == False:
                    printLog('[%s] Disconnected from %s port %s.' % (self.name, self.mb_config_item['host'] if 'host' in self.mb_config_item else 'local', self.mb_config_item['port']), 'error')
                    self.mb_client = mb_connect(self.mb_config_item['type'], host=self.mb_config_item['host'], port=self.mb_config_item['port'], mb_timeout=self.mb_config_item['timeout_seconds'])
                    self.current_log_timer = 0
                break

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
                register_value_precision = 0 if 'precision' not in register_conversion else register_conversion['precision']

                for register_i in range(int(register_conversion['registers'][0]) + register_gap, int(register_conversion['registers'][1]) + register_gap + 1):
                    try:
                        current_registers.append(register_group_address[register_group['group_id']][register_i])
                    except:
                        continue

                if len(current_registers) > 0:
                    # register_value = decode_results(current_registers if register_conversion['data_type'] in ['dt1', 'dt2'] else convert_registers(current_registers, register_conversion['swap'] if 'swap' in register_conversion else None), register_conversion['data_type'])
                    register_value=mb_convert_registers(registers=current_registers, data_type=register_conversion['data_type'], swap_type=register_conversion['swap'] if 'swap' in register_conversion else None)
                    register_items[current_slave_id][register_conversion['name']] = round(register_value, register_value_precision) if register_value_precision != "none" else register_value
                    register_slave_ids[register_conversion['name']] = current_slave_id

        # Return the dict of already converted MODBUS registers data type along with the mapped device ID.
        return {'items': register_items if slave_id is None else register_items[slave_id], 'slaveIDs': register_slave_ids}

    def send_current_log(self, device_id: int, items: dict = None, insert_log: bool = False) -> bool:
        """
        Send the received EVC current/instantaneous log values to the database (or STDOUT for debugging purposes).

        Mandatory keyword argument:
        device_id: int; Device ID retrieved from the database for each EVC device.

        Optional keyword arguments:
        items: dict; The dict of item list of the EVC current log to be retrieved. Default: None.
        insert_log: bool; Whether to insert a new record for a newly connected EVC device or not. Default: False.
        """
        if insert_log == True:
            try:
                q_insert_current = "INSERT INTO " + self.db_tbl_prefix + "_current_log (deviceID) VALUES (%s)"
                self.db_cur.execute(q_insert_current, (device_id,))
            except:
                return False
        else:
            try:
                # Create the current log query template using dictionary.
                q_update_current_log = "UPDATE " + self.db_tbl_prefix + "_current_log SET "
                q_update_items = []
                for item_name in items:
                    q_update_items.append("%s = %%(%s)s" % (item_name, item_name))
                q_update_current_log += ", ".join(q_update_items) + " WHERE deviceID = " + str(device_id)

                self.db_cur.execute(q_update_current_log, items)
            except Exception as e:
                printLog('[%s] send_current_log(): %s' % (self.name, e), 'error')
                return False
        return True

    def send_archive_log(self, device_id: int, group_ids: list, kind: str, slave_id: int, retention: int = 0) -> dict:
        """
        Send the received EVC archive log values to the database (or STDOUT for debugging purposes).

        Mandatory keyword arguments:
        device_id: int; Device ID retrieved from the database for each EVC device.
        groups_ids: list; List of the configured group_id for the corresponding EVC archive log.
        kind: str; Archive log kind (usually one of this: hourly, daily, monthly).

        Optional keyword arguments:
        retention: int; The count of retention of the backlog EVC archive log from the newest to the oldest data. Default: 0.
        slave_id: int; The EVC device MODBUS slave ID. Default: 1.
        """
        success_status = 0

        if kind in ARCHIVE_LOG_LIST:
            # Get the configured group_id for the corresponding EVC archive log.
            archive_log_group_ids = self.get_log_group_ids(group_ids)
            
            all_archive_log_items = []

            # Iterate once if no/zero retention is specified.
            for n_iter in range(0 if retention == 0 else 1, retention + 1):
                if retention > 0:
                    for group_id_index in range(0, len(archive_log_group_ids)):
                        archive_log_group_ids[group_id_index]['gap'] = n_iter * archive_log_group_ids[group_id_index]['count']

                # MODBUS poll the EVC device.
                archive_log_items = self.get_evc_log(archive_log_group_ids, slave_id)['items']

                # Send the received MODBUS responses to STDOUT for debugging purposes only.
                if self.mb_config_item[kind]['debug'] is True:
                    print(archive_log_items)

                if retention > 0:
                    for group_id_index in range(0, len(archive_log_group_ids)):
                        del archive_log_group_ids[group_id_index]['gap']

                try:
                    # Insert the received MODBUS responses (EVC archive log items value) into the database; otherwise, throw an error.
                    q_insert_archive = "INSERT IGNORE INTO " + self.db_tbl_prefix + '_' + kind + " (deviceID, " + ', '.join(archive_log_items) + ") VALUES (" + str(device_id) + ", %(" + ")s, %(".join([item_name for item_name in archive_log_items]) + ")s)"
                    self.db_cur.execute(q_insert_archive, archive_log_items)
                    if self.db_cur.rowcount > 0:
                        all_archive_log_items.append(archive_log_items)
                except Exception as e:
                    printLog('[%s] send_archive_log(): %s during %s operation for device_id %s ' % (self.name, e, kind, device_id), 'error')
                    if retention == 0:
                        success_status = 2
                else:
                    if retention == 0:
                        success_status = 1
            
            # Return the EVC archive log items value along with the general success status.
            return {'items': all_archive_log_items, 'status': success_status}

    def run(self):
        # Open MariaDB database and then map the connection and the cursor for later use.
        [db_conn, self.db_cur] = db_open(self.db_conn_params)

        current_device_id = 0

        while not self.stop_me.is_set():
            # Pause between MODBUS device connection attempts if it fails.
            if (self.mb_client is None or (self.mb_client is not None and hasattr(self.mb_client, 'connected') and self.mb_client.connected == False)) and round(millis()*1000) - self.current_log_timer >= int(self.mb_config_item['current_log']['scan_interval_ms']):

                if self.mb_client is not None:
                    printLog('[%s] Disconnected from %s port %s.' % (self.name, self.mb_config_item['host'] if 'host' in self.mb_config_item else 'local', self.mb_config_item['port']), 'error')

                self.mb_client = mb_connect(self.mb_config_item['type'], host=self.mb_config_item['host'], port=self.mb_config_item['port'], mb_timeout=self.mb_config_item['timeout_seconds'])

                if self.mb_client.connected == True:
                    self.current_log_timer = 0
                else:
                    # Reset timer, waiting for the next cycle.
                    self.current_log_timer = round(millis()*1000)

            # Poll the EVC device when the current log scan time deadline is met.
            elif round(millis()*1000) - self.current_log_timer >= int(self.mb_config_item['current_log']['scan_interval_ms']) and self.mb_client.connected == True and self.is_alive():
                try:
                    db_conn.ping()
                except DBOperationalError as e:
                    printLog("[%s] Database connection error detected: %s. Reconnecting..." % (self.name, e), 'error')
                    [db_conn, self.db_cur] = db_open(self.db_conn_params)

                # Reset timer, waiting for the next cycle.
                self.current_log_timer = round(millis()*1000)

                if 'last_dtu' not in locals():
                    last_dtu = 0

                current_log_group_ids = self.get_log_group_ids(self.mb_config_item['current_log']['group_ids'])
                current_log_items = self.get_evc_log(current_log_group_ids)

                all_register_items = current_log_items['items']

                for current_slave_id in all_register_items:
                    register_items = all_register_items[current_slave_id]

                    if self.mb_config_item['current_log']['debug'] is True:
                        print(register_items)

                    if len(register_items) > 0:
                        if current_device_id == 0:
                            q_get_device_id = "SELECT id FROM " + self.db_tbl_prefix + "_devices WHERE mbmaster_name = %s AND slaveID = %s LIMIT 1"
                            self.db_cur.execute(q_get_device_id, (self.mb_config_item['name'], current_slave_id))

                            if self.db_cur.rowcount == 0:
                                self.db_cur.execute("INSERT INTO " + self.db_tbl_prefix + "_devices (`mbmaster_name`, `slaveID`) VALUES (%s, %s)", (self.mb_config_item['name'], current_slave_id))
                                continue

                            rows_device_id = self.db_cur.fetchone()

                            current_device_id = rows_device_id[0]
                            q_get_current = "SELECT id FROM " + self.db_tbl_prefix + "_current_log WHERE deviceID = %s"
                            self.db_cur.execute(q_get_current, (current_device_id,))

                            if self.db_cur.rowcount == 0:
                                self.send_current_log(current_device_id, insert_log=True)

                        # MODBUS poll to the EVC device
                        self.send_current_log(current_device_id, register_items)

                        if self.evctime_reg['name'] in register_items:
                            last_dtu_str = dt_utc_to_current(last_dtu, self.evctime_reg['data_type'])
                            current_dtu_str = dt_utc_to_current(register_items[self.evctime_reg['name']], self.evctime_reg['data_type'])

                            # Get hourly log when EVC hour has changed.
                            if (last_dtu_str.hour != current_dtu_str.hour or self.archive_log_failed['hourly_log'] == True) and ARCHIVE_LOG_ENABLED['hourly_log'] == True:
                                if self.send_archive_log(current_device_id, self.mb_config_item['hourly_log']['group_ids'], 'hourly_log', current_slave_id)['status'] != 1:
                                    self.archive_log_failed['hourly_log'] = True
                                else:
                                    self.archive_log_failed['hourly_log'] = False if self.archive_log_failed['hourly_log'] == True else self.archive_log_failed['hourly_log']

                            # Substract the last current time of the EVC device by the configured day_start_hour, only if day_start_hour > 0, for the relativity effect of the daily log and the monthly log.
                            if self.mb_config_item['daily_log']['day_start_hour'] > 0:
                                last_dtu_str -= timedelta(hours=self.mb_config_item['daily_log']['day_start_hour'])
                                current_dtu_str -= timedelta(hours=self.mb_config_item['daily_log']['day_start_hour'])

                            # Get daily log when EVC day has changed.
                            if (last_dtu_str.day != current_dtu_str.day or self.archive_log_failed['daily_log'] == True) and ARCHIVE_LOG_ENABLED['daily_log'] == True:
                                if self.send_archive_log(current_device_id, self.mb_config_item['daily_log']['group_ids'], 'daily_log', current_slave_id)['status'] != 1:
                                    self.archive_log_failed['daily_log'] = True
                                else:
                                    self.archive_log_failed['daily_log'] = False if self.archive_log_failed['daily_log'] == True else self.archive_log_failed['daily_log']

                            # Get monthly log when EVC month has changed.
                            if (last_dtu_str.month != current_dtu_str.month or self.archive_log_failed['monthly_log'] == True) and ARCHIVE_LOG_ENABLED['monthly_log'] == True:
                                if self.send_archive_log(current_device_id, self.mb_config_item['monthly_log']['group_ids'], 'monthly_log', current_slave_id)['status'] != 1:
                                    self.archive_log_failed['monthly_log'] = True
                                else:
                                    self.archive_log_failed['monthly_log'] = False if self.archive_log_failed['monthly_log'] == True else self.archive_log_failed['monthly_log']

                            # Add the last current time of the EVC device by the configured day_start_hour, only if day_start_hour > 0, to reverse the relativity effect above.
                            if self.mb_config_item['daily_log']['day_start_hour'] > 0:
                                last_dtu_str += timedelta(hours=self.mb_config_item['daily_log']['day_start_hour'])
                                current_dtu_str += timedelta(hours=self.mb_config_item['daily_log']['day_start_hour'])

                            # START - Check Request Log.
                            q_check_request_log = "SELECT id, archiveLog, logRetention FROM " + self.db_tbl_prefix + "_request_log WHERE deviceID = %s AND requestStatus = 0 AND archiveLog >= 0 AND archiveLog < %s"
                            self.db_cur.execute(q_check_request_log, (current_device_id, len(ARCHIVE_LOG_LIST)))

                            if self.db_cur.rowcount > 0:
                                rows_request_log = self.db_cur.fetchall()
                                for row_request_log in rows_request_log:
                                    if row_request_log[2] <= self.mb_config_item[ARCHIVE_LOG_LIST[row_request_log[1]]]['max_retention'] and ARCHIVE_LOG_ENABLED[ARCHIVE_LOG_LIST[row_request_log[1]]] == True:
                                        if len(self.send_archive_log(current_device_id, self.mb_config_item[ARCHIVE_LOG_LIST[row_request_log[1]]]['group_ids'], ARCHIVE_LOG_LIST[row_request_log[1]], current_slave_id, row_request_log[2])['items']) > 0:
                                            q_request_log_status = 1
                                        else:
                                            q_request_log_status = 2
                                    else:
                                        q_request_log_status = 2

                                    q_update_request_log = "UPDATE " + self.db_tbl_prefix + "_request_log SET requestStatus = %s WHERE id = %s"
                                    self.db_cur.execute(q_update_request_log, (q_request_log_status, row_request_log[0]))
                            # END - Check Request Log.

                            # Time mark for the last EVC current log MODBUS poll.
                            last_dtu = register_items[self.evctime_reg['name']]
            try:
                sleep(0.1)
            except:
                break
        
        if self.mb_client is not None and hasattr(self.mb_client, 'connected') and self.mb_client.connected == True:
            mb_close(self.mb_client)
        db_close(db_conn)

    def shutdown(self):
        self.stop_me.set()