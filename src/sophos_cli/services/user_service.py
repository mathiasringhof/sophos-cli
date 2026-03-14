"""Service layer for explicit user-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class UserService:
    """Service wrapper for explicit user commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_users(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_user(), "User")
        except SophosFirewallZeroRecords:
            return []

    def get_user(self, username: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_user(username=username), "User")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_user(self, username: str, payload: dict[str, object]) -> FirewallObject:
        user_payload = {"user": username, **payload}
        return normalize_object_dict(self._client.create_user(**user_payload))

    def update_user_password(self, username: str, new_password: str) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_user_password(username=username, new_password=new_password)
        )

    def delete_user(self, username: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="User", name=username, key="Name"))
