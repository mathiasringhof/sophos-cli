"""Service layer for explicit system-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_body, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class SystemService:
    """Service wrapper for explicit system commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def get_backup(self) -> FirewallObject:
        return response_body(self._client.get_backup())

    def update_backup(self, backup_params: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_backup(backup_params=backup_params))

    def list_notifications(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_notification(), "Notification")
        except SophosFirewallZeroRecords:
            return []

    def get_notification(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_notification(name=name), "Notification")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def list_notification_items(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_notification_list(), "NotificationList")
        except SophosFirewallZeroRecords:
            return []

    def get_notification_item(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_notification_list(name=name), "NotificationList")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def get_reports_retention(self) -> FirewallObject:
        return response_body(self._client.get_reports_retention())
