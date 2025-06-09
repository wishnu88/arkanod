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

import MySQLdb
import threading
from time import sleep
from .funcs import printLog

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
    except Exception as e:
        printLog(e, 'error')
        table_errors += 1
    else:
        printLog('Table %s is successfully created.' % table_name)

def db_open(db_params: dict) -> list:
    thread_name = threading.current_thread().getName()
    db_conn = None
    while db_conn == None:
        try:
            db_conn = MySQLdb.connect(**db_params)
            db_cur = db_conn.cursor()
            printLog("[%s] Database server CONNECTED." % thread_name)
        except MySQLdb.Error as e:
            printLog("[%s] ERROR connecting to the database: %s" % (thread_name, e), 'critical')
            sleep(0.1)
    
    return [db_conn, db_cur]

def db_close(db_conn: object):
    """
    A simple function to close a database connection.

    Mandatory keyword argument:
    db_conn: object; The database connection variable.
    """
    thread_name = threading.current_thread().getName()
    if isinstance(db_conn, object):
        printLog("[%s] Closing MariaDB database..." % thread_name)
        db_conn.close()
        del db_conn
