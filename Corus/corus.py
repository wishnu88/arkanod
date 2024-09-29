from iflag import CorusClient
from iflag.data import CorusString, Index
from iflag.parse import IFlagParameter
from decimal import Decimal

client = CorusClient.with_tcp_transport(address=("114.141.55.52", 23025))
client.startup()
# Read single value
client.read_parameters([IFlagParameter(id=0x5e, data_class=CorusString)])
