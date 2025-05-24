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
"""

import sys
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from pymodbus.transaction import (ModbusRtuFramer, ModbusAsciiFramer, ModbusSocketFramer)

from danismod.funcs import printLog

def convert_registers(registers, swap_type: str = "none"):
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

    if data_type == 'ignore':
        decoded = results.skip_bytes(8)
    elif data_type == 'bits':
        decoded = results.decode_bits()
    elif data_type == 'float16':
        decoded = results.decode_16bit_float()
    elif data_type == 'float32':
        decoded = results.decode_32bit_float()
    elif data_type == 'float64':
        decoded = results.decode_64bit_float()
    elif data_type == 'int8':
        decoded = results.decode_8bit_int()
    elif data_type == 'int16':
        decoded = results.decode_16bit_int()
    elif data_type == 'int32':
        decoded = results.decode_32bit_int()
    elif data_type == 'int64':
        decoded = results.decode_64bit_int()
    elif data_type == 'string':
        decoded = results.decode_string()
    elif data_type == 'uint8':
        decoded = results.decode_8bit_uint()
    elif data_type == 'uint16':
        decoded = results.decode_16bit_uint()
    elif data_type == 'uint32':
        decoded = results.decode_32bit_uint()
    elif data_type == 'uint64':
        decoded = results.decode_64bit_uint()
    elif data_type == 'dt1':
        decoded = results.decode_32bit_uint()
    elif data_type == 'dt2':
        hex_values = ["{:04x}".format(register) for register in results]
        decoded = "".join(hex_values)

    return decoded

def mb_connect(type, port: str, host: str = None, mb_timeout: int = None):
    from arkanod.evc.main import is_running

    if is_running == False:
        return

    if type in ['rtuovertcp','tcp']:        
        try:
            printLog("Connecting to %s port %s..." % (host, port))
            if 'ModbusTcpClient' not in sys.modules:
                from pymodbus.client import ModbusTcpClient
            client = ModbusTcpClient(host=host, port=int(port), framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            printLog("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            printLog('Unable to establish connection to %s port %s.' % (host, port), 'error')
    elif type == 'rtu':        
        try:
            printLog("Connecting to port %s..." % port)
            if 'ModbusSerialClient' not in sys.modules:
                from pymodbus.client import ModbusSerialClient
            client = ModbusSerialClient(port=port, framer=ModbusRtuFramer if type == 'rtu' or type == 'rtuovertcp' else ModbusSocketFramer if type == 'tcp' else ModbusAsciiFramer, timeout=mb_timeout)
            client.connect()
            printLog("Connected succesfully to %s port %s!" % (host, port))
            return client
        except:
            printLog('Unable to establish connection to %s port %s.' % (host, port), 'error')

def modbus_close(client: object):
    if isinstance(client, object) and len(client) > 0:
        printLog("Disconnecting from Modbus devices...")
        for client_conn in client:
            if client[client_conn].connected == True:
                client[client_conn].close()
        del client