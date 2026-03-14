"""Service layer for explicit zone-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_body, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class ZoneService:
    """Service wrapper for explicit zone commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_zones(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_zone(), "Zone")
        except SophosFirewallZeroRecords:
            return []

    def get_zone(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_zone(name=name), "Zone")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_zone(self, name: str, zone_type: str, zone_params: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_zone(name=name, zone_type=zone_type, zone_params=zone_params or None)
        )

    def update_zone(self, name: str, zone_params: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_zone(name=name, zone_params=zone_params or None))

    def delete_zone(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="Zone", name=name, key="Name"))

    def list_interfaces(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_interface(), "Interface")
        except SophosFirewallZeroRecords:
            return []

    def get_interface(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_interface(name=name), "Interface")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def list_vlans(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_vlan(), "VLAN")
        except SophosFirewallZeroRecords:
            return []

    def get_vlan(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_vlan(name=name), "VLAN")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def get_dns_forwarders(self) -> FirewallObject:
        return response_body(self._client.get_dns_forwarders())
