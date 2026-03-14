"""Service layer for explicit admin-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_body, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class AdminService:
    """Service wrapper for explicit admin commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_profiles(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_admin_profile(), "AdministrationProfile")
        except SophosFirewallZeroRecords:
            return []

    def get_profile(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_admin_profile(name=name), "AdministrationProfile")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_profile(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.create_admin_profile(name=name, **payload))

    def update_profile(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_admin_profile(name=name, **payload))

    def delete_profile(self, name: str) -> FirewallObject:
        return normalize_object_dict(
            self._client.remove(xml_tag="AdministrationProfile", name=name, key="Name")
        )

    def get_authentication(self) -> FirewallObject:
        return response_body(self._client.get_admin_authen())

    def get_settings(self) -> FirewallObject:
        return response_body(self._client.get_admin_settings())
