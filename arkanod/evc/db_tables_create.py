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

from .db_const import DATA_TYPE, OPER_TABLES, TRIGGER_REQ_DATALOG, EVENT_NOT_UPDATE_CHECK
from danismod.db_funcs import check_table_exists, create_table_exec
import mariadb

def init_create_tables(db_cur: object):
    from .main import db_config_detail, register_conversion_fields, mb_config_check_item, app_exit, printLog
    table_errors = 0
    for oper_table in OPER_TABLES:
        index_failed = 0
        table_name = db_config_detail[0]['tbl_prefix'] + '_' + oper_table

        if check_table_exists(table_name, db_config_detail[0]['db_name'], db_cur):
            printLog('Table %s is already exists, skipping.' % table_name)
            continue

        create_table_exec(table_name, "CREATE TABLE %s " % table_name + OPER_TABLES[oper_table], db_cur)

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
                    db_cur.execute(TRIGGER_REQ_DATALOG % (table_name, db_config_detail[0]['tbl_prefix'], db_config_detail[0]['tbl_prefix'], db_config_detail[0]['tbl_prefix']))
                except mariadb.Error as e:
                    printLog("Failed to create trigger for table %s: %s" % (table_name, e), 'error')
                    index_failed += 1
        
        if index_failed > 0:
            db_cur.execute('DROP TABLE %s' % table_name)
            printLog("Rolling back create table %s." % table_name, 'error')
            table_errors += 1

    for log_table in register_conversion_fields:
        index_failed = 0
        table_name = db_config_detail[0]['tbl_prefix'] + '_' + log_table
        fields_created = []
        table_fields = []
        if check_table_exists(table_name, db_config_detail[0]['db_name'], db_cur):
            printLog('Table %s is already exists, skipping.' % table_name)
            continue

        q_create_table = ("CREATE TABLE %s (`id` %sINT AUTO_INCREMENT PRIMARY KEY, deviceID INT NOT NULL, " % (table_name, 'BIG' if log_table == 'hourly_log' else ''))
        for item_field in register_conversion_fields[log_table]:
            if item_field['item'] not in fields_created:
                fields_created.append(item_field['item'])
                table_fields.append("`" + item_field['item'] + "` %s" % DATA_TYPE[item_field['data_type']])
        q_create_table += ", ".join(table_fields) + ", LastUpdated DATETIME DEFAULT current_timestamp() ON UPDATE CURRENT_TIMESTAMP()) ENGINE=" + ("InnoDB" if log_table != "current_log" else "MyISAM") + " DEFAULT CHARSET=utf8mb4"
        create_table_exec(table_name, q_create_table, db_cur)

        if log_table != "current_log":
            try:
                db_cur.execute('ALTER TABLE `%s` ADD UNIQUE KEY `unique_log` (`deviceID`,`%s`)' % (table_name, mb_config_check_item[log_table]['log_time_regname']))
            except:
                printLog("Failed to create index for table %s. Insufficient privilege?" % table_name, 'error')
                index_failed += 1
        else:
            try:
                db_cur.execute('CREATE TRIGGER `UPDATE_CHECK` AFTER UPDATE ON `%s` FOR EACH ROW UPDATE %s_update_check SET Date_End = NEW.LastUpdated WHERE deviceID = NEW.deviceID AND Date_End IS NULL' % (table_name, db_config_detail[0]['tbl_prefix']))
            except:
                printLog("Failed to create trigger for table %s. Insufficient privilege?" % table_name, 'error')
                index_failed += 1

        if index_failed > 0:
            db_cur.execute('DROP TABLE %s' % table_name)
            printLog("Rolling back create table %s." % table_name, 'error')
            table_errors += 1

    try:
        db_cur.execute(EVENT_NOT_UPDATE_CHECK % (db_config_detail[0]['tbl_prefix'], db_config_detail[0]['tbl_prefix'], db_config_detail[0]['tbl_prefix'], db_config_detail[0]['tbl_prefix']))
    except:
        printLog("Failed to create event on database %s. Insufficient privilege?" % db_config_detail[0]['db_name'], 'error')
        table_errors += 1

    if table_errors > 0:
        printLog("WARNING: Not all table created successfully. Run this again after fixing the error(s).", 'error')

    app_exit(table_errors)
