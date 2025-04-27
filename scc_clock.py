#!/usr/bin/env python3

from pymodbus.client import ModbusTcpClient
from pymodbus.transaction import ModbusRtuFramer as ModbusFramer
from sys import argv
from datetime import datetime

client = ModbusTcpClient(host='192.168.85.131', port=8899, framer=ModbusFramer)
client.connect()

current_time = datetime.now()
print(current_time)
result = client.read_holding_registers(0, 3, slave=int(argv[1]))
print(result.bits)

