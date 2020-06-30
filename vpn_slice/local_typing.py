from ipaddress import (
    IPv4Address,
    IPv4Interface,
    IPv4Network,
    IPv6Address,
    IPv6Interface,
    IPv6Network,
)
from typing import Union

IPAddress = Union[IPv4Address, IPv6Address]
IPInterface = Union[IPv4Interface, IPv6Interface]
IPNetwork = Union[IPv4Network, IPv6Network]
