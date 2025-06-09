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

The danismod module MODBUS functions initialization file.
Depend heavily on pyModbus.
"""

import sys
import threading
from pymodbus import FramerType

from danismod.funcs import printLog

def mb_connect(type: str, port: str, host: str = None, mb_timeout: int = None):
    """
    Connect to the EVC device using the MODBUS protocol.

    Mandatory keyword arguments:
    type: str; The MODBUS protocol type (rtu, rtuovertcp, tcp).
    port: str; The MODBUS TCP port of the EVC device.
    host: str; The MODBUS TCP host name or IP of the EVC device. Usually used when type is rtuovertcp or tcp.

    Optional keyword argument:
    mb_timeout: int; The MODBUS response timeout in seconds. Default: None (pyModbus defined default).
    """
    thread_name = threading.current_thread().getName()

    if type in ['rtuovertcp','tcp']:        
        try:
            printLog("[%s] Connecting to %s port %s..." % (thread_name, host, port))
            if 'ModbusTcpClient' not in sys.modules:
                from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(host=host, port=int(port), framer=FramerType.RTU if type == 'rtu' or type == 'rtuovertcp' else FramerType.SOCKET if type == 'tcp' else FramerType.ASCII, timeout=mb_timeout)
            client.connect()
            printLog("[%s] Connected succesfully to %s port %s!" % (thread_name, host, port))
            return client
        except:
            printLog('[%s] Unable to establish connection to %s port %s.' % (thread_name, host, port), 'error')
    elif type == 'rtu':        
        try:
            printLog("[%s] Connecting to port %s..." % (thread_name, port))
            if 'ModbusSerialClient' not in sys.modules:
                from pymodbus.client import ModbusSerialClient
            client = ModbusSerialClient(port=port, framer=FramerType.RTU if type == 'rtu' or type == 'rtuovertcp' else FramerType.SOCKET if type == 'tcp' else FramerType.ASCII, timeout=mb_timeout)
            client.connect()
            printLog("[%s] Connected succesfully to %s port %s!" % (thread_name, host, port))
            return client
        except:
            printLog('[%s] Unable to establish connection to %s port %s.' % (thread_name, host, port), 'error')

def mb_convert_registers(registers: list, data_type: str, swap_type: str = "none") -> object:
    """
    Convert the MODBUS response byte from the EVC device to the configured data type and swap type.

    Mandatory keyword argument:
    registers: list; The MODBUS message response from configured registers.
    data_type: str; The configured data type.

    Optional keyword argument:
    swap_type: str; Byte swap type of the MODBUS message responses (none, word, word_byte). Default: none.
    """
    from pymodbus.client.mixin import ModbusClientMixin
    from pymodbus.constants import Endian

    decoded = None
    if data_type == 'float32':
        data_type_class = ModbusClientMixin.DATATYPE.FLOAT32
    elif data_type == 'float64':
        data_type_class = ModbusClientMixin.DATATYPE.FLOAT64
    elif data_type == 'int16':
        data_type_class = ModbusClientMixin.DATATYPE.INT16
    elif data_type == 'int32':
        data_type_class = ModbusClientMixin.DATATYPE.INT32
    elif data_type == 'int64':
        data_type_class = ModbusClientMixin.DATATYPE.INT64
    elif data_type == 'string':
        data_type_class = ModbusClientMixin.DATATYPE.STRING
    elif data_type == 'uint16':
        data_type_class = ModbusClientMixin.DATATYPE.UINT16
    elif data_type == 'uint32' or data_type == 'dt1':
        data_type_class = ModbusClientMixin.DATATYPE.UINT32
    elif data_type == 'uint64':
        data_type_class = ModbusClientMixin.DATATYPE.UINT64
    elif data_type == 'dt2':
        hex_values = ["{:04x}".format(register) for register in registers]
        decoded = "".join(hex_values)

    return ModbusClientMixin.convert_from_registers(registers, data_type=data_type_class, word_order=Endian.LITTLE if swap_type == 'word' else Endian.BIG) if decoded is None else decoded

def mb_close(client: object):
    """
    A simple function to close a MODBUS connection.

    Mandatory keyword argument:
    client: object; The MODBUS connection variable.
    """
    thread_name = threading.current_thread().getName()

    if isinstance(client, object):
        printLog("[%s] Disconnecting from %s..." % (thread_name, client))
        client.close()
