"""Thin wrapper around the sophosfirewall-python SDK client."""

from typing import cast

from sophosfirewall_python.firewallapi import SophosFirewall

from sophos_cli.connection import ConnectionParams
from sophos_cli.firewall_client import FirewallClientProtocol


def create_client(connection: ConnectionParams) -> FirewallClientProtocol:
    """Create a configured Sophos Firewall SDK client."""

    client = SophosFirewall(
        username=connection.username,
        password=connection.password,
        hostname=connection.host,
        port=connection.port,
        verify=connection.verify_ssl,
    )
    return cast(FirewallClientProtocol, client)
