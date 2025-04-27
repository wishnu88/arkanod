#!/usr/bin/env python3

from pymodbus.client import ModbusTcpClient
from pymodbus.transaction import ModbusRtuFramer as ModbusFramer
from pymodbus.constants import Endian
from pymodbus.payload import BinaryPayloadDecoder
from sys import argv
from datetime import datetime

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

    if data_type == 'float16':
        decoded = results.decode_16bit_float()
    elif data_type == 'float32':
        decoded = results.decode_32bit_float()
    elif data_type == 'float64':
        decoded = results.decode_64bit_float()
    elif data_type == 'int16':
        decoded = results.decode_16bit_int()
    elif data_type == 'int32':
        decoded = results.decode_32bit_int()
    elif data_type == 'int64':
        decoded = results.decode_64bit_int()
    elif data_type == 'string':
        decoded = results.decode_string()
    elif data_type == 'uint16':
        decoded = results.decode_16bit_uint()
    elif data_type == 'uint32':
        decoded = results.decode_32bit_uint()
    elif data_type == 'uint64':
        decoded = results.decode_64bit_uint()
    elif data_type == 'dt1':
        decoded = results.decode_32bit_uint()
    elif data_type == 'dt2':
        hex_values = ["{:02x}".format(register) for register in results]
        decoded = "".join(hex_values)

    return decoded

client = ModbusTcpClient(host='192.168.85.131', port=8899, framer=ModbusFramer)
client.connect()

current_time = datetime.now()
print(current_time)
result = client.read_holding_registers(0, 3, slave=int(argv[1]))
print(result.__dict__)

#hex_values = ["{:02x}".format(register) for register in result.registers]
#print("".join(hex_values))
print(decode_results(result.registers, 'dt2'))
