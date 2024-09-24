#!/usr/bin/env python3

from pymodbus.client import ModbusTcpClient
from pymodbus.transaction import ModbusRtuFramer as ModbusFramer
from sys import argv
from datetime import datetime

client = ModbusTcpClient(host='114.141.55.52', port=23026, framer=ModbusFramer)
client.connect()

current_time = datetime.now()
print(current_time)
result = client.read_holding_registers(69, 2, slave=int(argv[1]))
print(result.registers)

