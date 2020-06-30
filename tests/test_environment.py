from inspect import isclass
from ipaddress import ip_interface, ip_network

import pytest

from vpn_slice.environment import get_splits, interface_from_addr_mask_len


@pytest.mark.parametrize(
    "addr,mask,masklen,expected",
    [
        ("192.0.2.1", None, None, ip_interface("192.0.2.1/32")),
        ("192.0.2.1", "255.255.255.0", None, ip_interface("192.0.2.1/24")),
        ("192.0.2.1", None, "24", ip_interface("192.0.2.1/24")),
        ("192.0.2.1", "255.255.255.0", "24", ip_interface("192.0.2.1/24")),
        ("192.0.2.1", "255.255.255.0", "20", ValueError),
        ("2001:db8::1", None, None, ip_interface("2001:db8::1/128")),
        ("2001:db8::1", "2001:db8::1/64", None, ip_interface("2001:db8::1/64")),
        ("2001:db8::1", "2001:db8::/64", None, ip_interface("2001:db8::1/64")),
    ],
)
def test_interface_from_addr_mask_len(addr, mask, masklen, expected):
    if isclass(expected):
        with pytest.raises(expected):
            interface_from_addr_mask_len(addr, mask, masklen)
    else:
        assert interface_from_addr_mask_len(addr, mask, masklen) == expected


def test_get_splits():
    environ = {
        "CISCO_SPLIT_INC": "2",
        "CISCO_SPLIT_INC_0_ADDR": "192.0.2.0",
        "CISCO_SPLIT_INC_0_MASKLEN": "24",
        "CISCO_SPLIT_INC_1_ADDR": "198.51.100.0",
        "CISCO_SPLIT_INC_1_MASKLEN": "24",
    }
    assert get_splits("CISCO_SPLIT_INC", environ) == {
        ip_network("192.0.2.0/24"),
        ip_network("198.51.100.0/24"),
    }
