# -*- coding: utf-8 -*-
"""
Poll EVC (Electronic Volume Corrector) data and archive log periodically using the 0-based address MODBUS protocol.

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

The evc module create tables procedure file.
"""

from danismod.db_funcs import *
from .db_const import DATA_TYPE, OPER_TABLES, TRIGGER_REQ_DATALOG, EVENT_NOT_UPDATE_CHECK
from danismod.funcs import printLog
from main import app_exit

def init_create_tables(db_params: dict, register_conversion_fields: dict, mb_config_check_item: dict):
    """
    The procedure to initiate the database tables. It is usually fired when --create-tables is called from the main program.

    Mandatory keyword argument:
    db_cur: object; The database cursor variable.
    """
    table_errors = 0
    db_conn_params = {
        'host': db_params['db_host'],
        'port': db_params['db_port'],
        'user': db_params['db_username'],
        'password': db_params['db_password'],
        'database': db_params['db_name'],
        'autocommit': True,
        # 'reconnect': True
    }

    [db_conn, db_cur] = db_open(db_conn_params)
    
    def rollback_table(table_name: str, table_errors: int = table_errors):
        """ A simple procedure to drop the already created table. It requires only one keyword argument: table_name; str. """

        if index_failed > 0:
            db_cur.execute('DROP TABLE %s' % table_name)
            printLog("Rolling back create table %s." % table_name, 'error')
            table_errors += 1

    def create_trigger_update_check():
        # Create a trigger for the update_check table when it is updated.
        q_trigger_req_datalog = TRIGGER_REQ_DATALOG % (db_params['tbl_prefix'], table_name, db_params['tbl_prefix'], db_params['tbl_prefix'], db_params['tbl_prefix'])
        db_cur.execute(q_trigger_req_datalog)

    def create_trigger_current_log():
        # Create a trigger for the current_log table when it is updated.
        db_cur.execute('CREATE TRIGGER IF NOT EXISTS `' + db_params['tbl_prefix'] + '_UPDATE_CHECK` AFTER UPDATE ON `' + table_name + '` FOR EACH ROW UPDATE ' + db_params['tbl_prefix'] + '_update_check SET Date_End = NEW.LastUpdated WHERE deviceID = NEW.deviceID AND Date_End IS NULL')

    # Iterate through the available tables needed for runtime operation.
    for oper_table in OPER_TABLES:
        index_failed = 0
        table_name = db_params['tbl_prefix'] + '_' + oper_table

        if check_table_exists(table_name, db_params['db_name'], db_cur):
            printLog('Table %s is already exists, skipping.' % table_name)
            if oper_table == 'update_check':
                create_trigger_update_check()
            continue
        
        # Create an operation table.
        create_table_exec(table_name, "CREATE TABLE %s " % table_name + OPER_TABLES[oper_table], db_cur)

        # Create the needed index for an operation table, except for the update_check table.
        if oper_table == 'devices':
            try:
                db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `unique_dev` (`mbmaster_name`,`slaveID`)' % table_name)
            except:
                printLog("Failed to create index for table %s. Insufficient privilege?" % table_name, 'error')
                index_failed += 1
        elif oper_table == 'update_check':
            try:
                db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `deviceID` (`deviceID`)' % table_name)
            except:
                printLog("Failed to create index for table %s. Insufficient privilege?" % table_name, 'error')
                index_failed += 1
            else:
                try:
                    create_trigger_update_check()
                # Throw an error if the index creation fails.
                except Exception as e:
                    printLog("Failed to create trigger for table %s: %s" % (table_name, e), 'error')
                    index_failed += 1
        
        # Drop the table if the index creation fails.
        rollback_table(table_name)

    # Iterate through the available tables needed for saving the EVC logs.
    for log_table in register_conversion_fields:
        index_failed = 0
        table_name = db_params['tbl_prefix'] + '_' + log_table
        fields_created = []
        table_fields = []
        if check_table_exists(table_name, db_params['db_name'], db_cur):
            printLog('Table %s is already exists, skipping.' % table_name)
            continue

        # Create an EVC log table creation query template, using the configured register_conversion items as the table fields.
        q_create_table = ("CREATE TABLE %s (`id` %sINT AUTO_INCREMENT PRIMARY KEY, deviceID INT NOT NULL, " % (table_name, 'BIG' if log_table == 'hourly_log' else ''))
        for item_field in register_conversion_fields[log_table]:
            if item_field['item'] not in fields_created:
                fields_created.append(item_field['item'])
                table_fields.append("`" + item_field['item'] + "` %s" % DATA_TYPE[item_field['data_type']])
        q_create_table += ", ".join(table_fields) + ", LastUpdated DATETIME DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP()) ENGINE=" + ("InnoDB" if log_table != "current_log" else "MyISAM") + " DEFAULT CHARSET=utf8mb4"

        # Create an EVC log table using the above query template.
        create_table_exec(table_name, q_create_table, db_cur)

        # Create the needed index for an EVC log table, except for the current_log table.
        if log_table != "current_log":
            try:
                db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `unique_log` (`deviceID`,`%s`)' % (table_name, mb_config_check_item[log_table]['log_time_regname']))

            # Throw an error if the index creation fails.
            except Exception as e:
                printLog("Failed to create index for table %s: %s" % (table_name, e), 'error')
                index_failed += 1
        else:
            # Instead of creating an index, we create a trigger for the current_log table when it is updated.
            try:
                create_trigger_current_log()
            # Throw an error if the trigger creation fails.
            except Exception as e:
                printLog("Failed to create trigger for table %s: %s" % (table_name, e), 'error')
                index_failed += 1

        # Drop the table if the index and/or trigger creation fails.
        rollback_table(table_name)

    # Create a database event to obtain the EVC devices that are not updated.
    try:
        q_not_update_check = EVENT_NOT_UPDATE_CHECK % (db_params['tbl_prefix'], db_params['tbl_prefix'], db_params['tbl_prefix'], db_params['tbl_prefix'], db_params['tbl_prefix'])
        db_cur.execute(q_not_update_check)
    except Exception as e:
        printLog("Failed to create event on database %s: %s" % (db_params['db_name'], e), 'error')
        table_errors += 1

    # Throw a warning explaining that there is at least one table failed to be created.
    if table_errors > 0:
        printLog("WARNING: Not all table created successfully. Run this again after fixing the error(s).", 'error')

    db_close(db_conn)
    app_exit(table_errors)
