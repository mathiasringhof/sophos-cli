"""Thin wrapper around the sophosfirewall-python SDK client."""

from sophosfirewall_python.firewallapi import SophosFirewall


def create_client(
    *,
    host: str,
    username: str,
    password: str,
    port: int,
    verify_ssl: bool,
) -> SophosFirewall:
    """Create a configured Sophos Firewall SDK client."""

    return SophosFirewall(
        username=username,
        password=password,
        hostname=host,
        port=port,
        verify=verify_ssl,
    )
