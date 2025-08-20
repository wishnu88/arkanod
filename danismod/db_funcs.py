# -*- coding: utf-8 -*-
"""
Danismod - A collection of functions and procedures involved in Arkanod development.

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

The danismod module database functions initialization file.
"""

import sys
import threading
from time import sleep

import yaml
import MySQLdb

from arkanod.evc.db_const import OPER_TABLES
from arkanod.evc.const import ARCHIVE_LOG_LIST
from .funcs import print_log

def check_table_exists(table_name: str, db_name: str, db_cur: object) -> bool:
    """
    A simple function to check whether a table exists in a database.

    Mandatory keyword arguments:
    table_name: str; The table name to be checked.
    db_name: str; The database name.
    db_cur: object; The database cursor.
    """
    db_cur.execute("SHOW TABLE STATUS FROM " + db_name + " WHERE Name = %s", (table_name,))
    if db_cur.rowcount > 0:
        return True
    return False

def create_table_exec(table_name: str, query: str, db_cur: object):
    """
    A simple function to execute a query template to create a table in a database.

    Mandatory keyword arguments:
    table_name: str; The table name to be created.
    query: str; The database query template.
    db_cur: object; The database cursor.
    """
    try:
        db_cur.execute(query)
    except MySQLdb.Error as e:
        print_log(e, 'error')
    else:
        print_log(f"Table {table_name} is successfully created.")

def db_open(db_config: dict) -> list:
    """
    A simple function to open a connection to the database system.

    Mandatory keyword argument:
    db_config: dict; A dictionary of database connection credentials.
    """
    thread_name = threading.current_thread().name
    db_conn = None

    while db_conn is None:
        try:
            db_conn = MySQLdb.connect(**db_config)
            db_cur = db_conn.cursor()
            print_log(f"[{thread_name}] Database server CONNECTED.")
        except MySQLdb.Error as e:
            print_log(f"[{thread_name}] ERROR connecting to the database: {e}", 'critical')
            sleep(0.1)
            if sys._getframe(1).f_code.co_name == 'db_config_check': #pylint: disable=protected-access
                return [None, None]

    return [db_conn, db_cur]

def db_close(db_conn: object):
    """
    A simple function to close a database connection.

    Mandatory keyword argument:
    db_conn: object; The database connection variable.
    """
    thread_name = threading.current_thread().name
    if isinstance(db_conn, object):
        print_log(f"[{thread_name}] Closing database...")
        db_conn.close()
        del db_conn

def db_config_check() -> dict | bool:
    """
    A procedure to perform a complete database existence check before going to the main program.
    It will return a boolean False if the check fails; otherwise, it will return the dictionary of
    the database connection and its cursor. 
    """
    error_len = 0

    # Read <base_dir>/config/db.yaml file for database configuration. Will be supporting multiple
    # databases and DBMS in the future.
    try:
        with open('config/db.yaml', 'r', encoding='utf-8') as db_config:
            print_log('Loading database settings from config/db.yaml...')
            db_config_check_var = db_config_detail = yaml.safe_load(db_config)
    except OSError as e:
        print_log(f"Unable to open config/db.yaml file: {e}")
        return False

    # START - DB config sanity check and default value.
    if len(db_config_check_var) > 0:
        for db_item_index, db_instance in enumerate(db_config_check_var):
            for db_param_name in ['db_instance','db_host','db_username','db_password','db_name']:
                if db_param_name not in db_instance:
                    error_len += 1
                    if db_param_name == 'db_instance':
                        print_log(f"[config/db.yaml - Item {db_item_index}] Unable to find the "
                                  f"valid {db_param_name} configuration.", 'error')
                        break
                    print_log(f"[config/db.yaml - Item {db_item_index}] Unable to find "
                              f"{db_param_name} configuration for instance "
                              f"{db_instance['db_instance']}.", 'error')
                elif db_param_name in db_instance and db_instance[db_param_name] == "":
                    if db_param_name == 'db_instance':
                        print_log(f"[config/db.yaml - Item {db_item_index}] db_instance "
                                  "configuration cannot be empty.", 'error')
                    else:
                        print_log(f"[config/db.yaml - Item {db_item_index}] Invalid {db_param_name}"
                                  f" configuration for instance {db_instance['db_instance']}.",
                                  'error')
                    error_len += 1

            if 'db_port' not in db_instance:
                print_log(f"[config/db.yaml - Item {db_item_index}] Unable to find db_port "
                          "configuration. Assuming TCP/3306 as the DB port.", 'debug')
                db_config_detail[db_item_index]['db_port'] = 3306
            elif 'db_port' in db_instance:
                if ((isinstance(db_instance['db_port'], int) and
                    (db_instance['db_port'] < 1 or
                    db_instance['db_port'] > 65535)) or
                    isinstance(db_instance['db_port'], int) is False):
                    print_log(f"[config/db.yaml - Item {db_item_index}] Invalid db_port "
                              "configuration.", 'error')
                    error_len += 1

    if error_len > 0:
        return False

    if len(sys.argv) == 2 and sys.argv[1] == '--create-tables':
        pass
    else:
        for db_config in db_config_detail:
            db_conn_params = {
                'host': db_config['db_host'],
                'port': db_config['db_port'],
                'user': db_config['db_username'],
                'password': db_config['db_password'],
                'database': db_config['db_name'],
                'autocommit': True,
                # 'reconnect': True
            }
            [db_conn, db_cur] = db_open(db_conn_params)
            if db_cur is None:
                return False
            for the_table in [*OPER_TABLES, *ARCHIVE_LOG_LIST]:
                table_name = db_config['tbl_prefix'] + '_' + the_table
                if not check_table_exists(table_name, db_config['db_name'], db_cur):
                    print_log(f"Table {table_name} is not exists in database "
                              f"{db_config['db_name']}.", 'error')
                    error_len += 1

        if error_len == 0:
            # Check whether the 2 triggers have already been created.
            q_check_trigger = "SHOW TRIGGERS LIKE '" + db_config['tbl_prefix'] + "\\_%'"
            db_cur.execute(q_check_trigger)
            if db_cur.rowcount != 2:
                print_log(f"Missing triggers in database {db_config['db_name']}.", 'error')
                error_len += 1

            q_check_event = "SHOW EVENTS FROM " + db_config['db_name'] + " LIKE '" + \
                db_config['tbl_prefix'] + "_NOT_UPDATE_CHECK'"
            db_cur.execute(q_check_event)
            if db_cur.rowcount != 1:
                print_log(f"Missing event in database {db_config['db_name']}.", 'error')
                error_len += 1

        if error_len > 0:
            print_log("Run arkanod with the '--create-tables' option to solve the issue(s).",
                      'error')
            db_close(db_conn)
            return False

    print_log('Database configuration loaded and checked successfully.')
    return db_config_detail
    # END - DB config sanity check and default value.
