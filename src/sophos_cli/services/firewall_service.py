"""Service layer for explicit firewall-domain resources."""

from __future__ import annotations

from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.command_support import normalize_object_dict, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject


class FirewallService:
    """Service wrapper for explicit firewall commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_rules(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_rule(), "FirewallRule")
        except SophosFirewallZeroRecords:
            return []

    def get_rule(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_rule(name=name), "FirewallRule")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_rule(self, name: str, rule_params: dict[str, object]) -> FirewallObject:
        payload = {"rulename": name, **rule_params}
        return normalize_object_dict(self._client.create_rule(rule_params=payload))

    def update_rule(self, name: str, rule_params: dict[str, object]) -> FirewallObject:
        merged_rule_params = dict(rule_params)
        if "status" not in merged_rule_params:
            existing = self.get_rule(name)
            existing_status = existing.get("Status") if existing else None
            if isinstance(existing_status, str) and existing_status:
                merged_rule_params["status"] = existing_status
        return normalize_object_dict(
            self._client.update_rule(name=name, rule_params=merged_rule_params)
        )

    def delete_rule(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="FirewallRule", name=name, key="Name"))

    def list_rule_groups(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_rulegroup(), "FirewallRuleGroup")
        except SophosFirewallZeroRecords:
            return []

    def get_rule_group(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_rulegroup(name=name), "FirewallRuleGroup")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_rule_group(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.create_rulegroup(name=name, **payload))

    def update_rule_group(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_rulegroup(name=name, **payload))

    def delete_rule_group(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="FirewallRuleGroup", name=name, key="Name"))

    def list_acl_rules(self) -> list[FirewallObject]:
        try:
            return response_records(self._client.get_acl_rule(), "LocalServiceACL")
        except SophosFirewallZeroRecords:
            return []

    def get_acl_rule(self, name: str) -> FirewallObject | None:
        try:
            records = response_records(self._client.get_acl_rule(name=name), "LocalServiceACL")
        except SophosFirewallZeroRecords:
            return None
        return records[0] if records else None

    def create_acl_rule(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.create_acl_rule(name=name, **payload))

    def update_acl_rule(self, name: str, payload: dict[str, object]) -> FirewallObject:
        return normalize_object_dict(self._client.update_acl_rule(name=name, **payload))

    def delete_acl_rule(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="LocalServiceACL", name=name, key="RuleName"))
