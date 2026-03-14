"""Service layer for explicit webfilter-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class WebFilterService:
    """Service wrapper for explicit webfilter commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_policies(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_webfilterpolicy(), "WebFilterPolicy")
        except SophosFirewallZeroRecords:
            return []

    def get_policy(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_webfilterpolicy(name=name), "WebFilterPolicy")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_policy(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.create_webfilterpolicy(name=name, **payload))

    def update_policy(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_webfilterpolicy(name=name, **payload))

    def delete_policy(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="WebFilterPolicy", name=name, key="Name"))

    def list_user_activities(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_useractivity(), "UserActivity")
        except SophosFirewallZeroRecords:
            return []

    def get_user_activity(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_useractivity(name=name), "UserActivity")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_user_activity(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.create_useractivity(name=name, **payload))

    def delete_user_activity(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="UserActivity", name=name, key="Name"))
