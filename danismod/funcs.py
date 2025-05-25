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

The danismod module general functions initialization file.
"""

def printLog(msg: str, level: str = 'info'):
    """
    Log to STDOUT (or another channel in the future) with the configured log level.

    Mandatory keyword argument:
    msg: str; Message to be logged.

    Optional keyword argument:
    level: str; The log level (info, debug, error, critical). Default: info.
    """
    import logging

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

def dt_utc_to_current(datetime_str: int, data_type: str = 'dt1'):
    """
    Convert the EVC device system date time to the database field datetime format.

    Mandatory keyword argument:
    datetime_str: str; The EVC device date time string.

    Optional keyword argument:
    data_type: str; The EVC device date time format type (dt1, dt2). Default: dt1.
    """
    import logging
    from datetime import datetime, timezone

    data_type = 'dt1' if data_type == 'dt2' and datetime_str == 0 else data_type

    # Basically, dt1 is a UNIX timestamp, while dt2 is taken from Corus Evo+ default date time format.
    if data_type == 'dt1':
        return datetime.strptime(str(datetime.fromtimestamp(datetime_str, timezone.utc)), '%Y-%m-%d %H:%M:%S%z')
    elif data_type == 'dt2':             
        return datetime.strptime(datetime_str, '%y%m%d%H%M%S')
