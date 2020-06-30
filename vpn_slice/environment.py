import os
from enum import Enum
from functools import wraps
from ipaddress import ip_address, ip_interface, ip_network
from typing import AbstractSet, Callable, Mapping, Optional, Set, TypeVar

import attr

from .local_typing import IPAddress, IPInterface, IPNetwork


Reason = Enum("Reason", "pre-init connect disconnect reconnect attempt-reconnect")

T = TypeVar("T")
U = TypeVar("U")


def optional(f: Callable[[T], U]) -> Callable[[Optional[T]], Optional[U]]:
    @wraps(f)
    def wrapper(x):
        if x is None:
            return x
        else:
            return f(x)

    return wrapper


def interface_from_addr_mask_len(
    addr: str, mask: Optional[str], masklen: Optional[str] = None
) -> IPInterface:
    ifs = set()
    if mask is not None:
        if "/" in mask:
            ifs.add(ip_interface((addr, ip_network(mask, strict=False).prefixlen)))
        else:
            # NOTE: The docs claim that `ip_interface((addr, mask))` will work,
            # but, in fact, that requries Python >=3.7.
            ifs.add(ip_interface('{}/{}'.format(addr, mask)))
    if masklen is not None:
        ifs.add(ip_interface((addr, int(masklen))))
    if not ifs:
        return ip_interface(addr)
    if len(ifs) != 1:
        raise ValueError(
            "{addr} netmask {mask} masklen {masklen} is inconsistent.".format(
                addr=addr, mask=mask, masklen=masklen
            )
        )
    return next(iter(ifs))


def get_splits(stem: str, environ: Mapping[str, str]) -> AbstractSet[IPNetwork]:
    count = int(environ[stem])
    result = set()
    for i in range(count):
        result.add(
            interface_from_addr_mask_len(
                environ["{stem}_{i}_ADDR".format(stem=stem, i=i)],
                environ.get("{stem}_{i}_MASK".format(stem=stem, i=i)),
                environ.get("{stem}_{i}_MASKLEN".format(stem=stem, i=i)),
            ).network
        )
    return frozenset(result)


@attr.s(frozen=True)
class Environment:
    reason = attr.ib()  # type: Reason
    gateway = attr.ib()  # type: IPAddress
    dev = attr.ib()  # type: str
    internal = attr.ib()  # type: AbstractSet[IPInterface]
    mtu = attr.ib()  # type: Optional[int]
    dns = attr.ib()  # type: AbstractSet[IPAddress]
    wins = attr.ib()  # type: AbstractSet[IPAddress]
    splits = attr.ib()  # type: AbstractSet[IPNetwork]
    search_domain = attr.ib()  # type: Optional[str]
    banner = attr.ib()  # type: Optional[str]

    @classmethod
    def from_environ(cls, environ: Mapping[str, str] = None) -> 'Environment':
        if environ is None:
            environ = os.environ

        internal = set()
        if "INTERNAL_IP4_ADDRESS" in environ:
            internal.add(
                interface_from_addr_mask_len(
                    environ["INTERNAL_IP4_ADDRESS"],
                    environ.get("INTERNAL_IP4_NETMASK"),
                    environ.get("INTERNAL_IP4_NETMASKLEN"),
                )
            )
        if "INTERNAL_IP6_ADDRESS" in environ:
            internal.add(
                interface_from_addr_mask_len(
                    environ["INTERNAL_IP6_ADDRESS"],
                    environ.get("INTERNAL_IP6_NETMASK"),
                )
            )
        elif "INTERNAL_IP6_NETMASK" in environ:
            internal.add(ip_interface(environ["INTERNAL_IP6_NETMASK"]))

        dns = set()  # type: Set[IPAddress]
        if "INTERNAL_IP4_DNS" in environ:
            dns.update(ip_address(a) for a in environ["INTERNAL_IP4_DNS"].split())
        if "INTERNAL_IP6_DNS" in environ:
            dns.update(ip_address(a) for a in environ["INTERNAL_IP6_DNS"].split())

        splits = set()  # type: Set[IPNetwork]
        if "CISCO_SPLIT_INC" in environ:
            splits.update(get_splits("CISCO_SPLIT_INC", environ))
        if "CISCO_IPV6_SPLIT_INC" in environ:
            splits.update(get_splits("CISCO_IPV6_SPLIT_INC", environ))

        return cls(
            reason=Reason[environ["reason"]],
            gateway=ip_address(environ["VPNGATEWAY"]),
            dev=environ["TUNDEV"],
            internal=frozenset(internal),
            mtu=optional(int)(environ.get("INTERNAL_IP4_MTU")),
            dns=frozenset(dns),
            wins=frozenset(
                ip_address(a) for a in environ.get("INTERNAL_IP4_NBNS", "").split()
            ),
            splits=frozenset(splits),
            search_domain=environ.get("CISCO_DEF_DOMAIN"),
            banner=environ.get("CISCO_BANNER"),
        )
