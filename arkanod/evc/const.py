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

The evc module general constants initialization file.
"""

MODBUS_TYPE_LIST = [
    'rtuovertcp',
    'rtu',
    'tcp',
    'ascii'
]

REGISTER_TYPE_LIST = [
    'coil',
    'input',
    'holding'
]

SWAP_TYPE_LIST = [
    'byte',
    'word',
    'word_byte',
    'none'
]

DATA_TYPE_LIST = [
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

ARCHIVE_LOG_LIST = [
    'hourly_log',
    'daily_log',
    'monthly_log'
]

ARCHIVE_LOG_FAILED = {
    'hourly_log': False,
    'daily_log': False,
    'monthly_log': False,
}

LOG_LEVEL = 2
