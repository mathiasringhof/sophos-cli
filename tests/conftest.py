from __future__ import annotations

from typing import cast

import pytest
import xmltodict
from sophosfirewall_python.api_client import SophosFirewallZeroRecords
from typer.testing import CliRunner

from sophos_cli.connection import ConnectionParams


class InMemoryFirewallClient:
    def __init__(self) -> None:
        self.entries: dict[str, dict[str, object]] = {}
        self.last_call: tuple[str, dict[str, object]] | None = None

    def seed_entry(self, host_name: str, ip_address: str) -> None:
        self.entries[host_name] = {
            "HostName": host_name,
            "AddressList": {
                "Address": {
                    "EntryType": "Manual",
                    "IPFamily": "IPv4",
                    "IPAddress": ip_address,
                    "TTL": "3600",
                    "Weight": "0",
                    "PublishOnWAN": "Disable",
                }
            },
            "AddReverseDNSLookUp": "Disable",
        }

    def login(self, output_format: str = "dict") -> dict[str, object]:
        del output_format
        self.last_call = ("login", {})
        return {"Response": {"Status": {"@code": "200", "#text": "Authentication Successful"}}}

    def get_tag(
        self,
        xml_tag: str,
        timeout: int = 30,
        output_format: str = "dict",
    ) -> dict[str, object]:
        del output_format
        self.last_call = ("get_tag", {"xml_tag": xml_tag, "timeout": timeout})

        if xml_tag != "DNSHostEntry":
            return {"Response": {xml_tag: {"Status": "ok"}}}

        if not self.entries:
            raise SophosFirewallZeroRecords("Number of records Zero.")

        values = list(self.entries.values())
        payload: object = values if len(values) > 1 else values[0]
        return {"Response": {"DNSHostEntry": payload}}

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "=",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> dict[str, object]:
        del output_format
        self.last_call = (
            "get_tag_with_filter",
            {
                "xml_tag": xml_tag,
                "key": key,
                "value": value,
                "operator": operator,
                "timeout": timeout,
            },
        )

        if xml_tag != "DNSHostEntry":
            return {"Response": {xml_tag: {"key": key, "value": value}}}

        if value not in self.entries:
            raise SophosFirewallZeroRecords("Number of records Zero.")

        return {"Response": {"DNSHostEntry": self.entries[value]}}

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict[str, object] | None = None,
        set_operation: str = "add",
        timeout: int = 30,
        debug: bool = False,
    ) -> dict[str, object]:
        del template_vars, timeout, debug

        payload = _normalize_object_dict(xmltodict.parse(template_data))
        entry = _normalize_object_dict(payload.get("DNSHostEntry"))
        host_name = str(entry.get("HostName", ""))

        if not host_name:
            raise ValueError("HostName is required")

        self.entries[host_name] = entry
        action = "Created" if set_operation == "add" else "Updated"
        return {"Response": {"DNSHostEntry": {"Status": {"@code": "200", "#text": action}}}}


def _normalize_object_dict(value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        return {}

    normalized: dict[str, object] = {}
    for key, item in cast(dict[object, object], value).items():
        if isinstance(key, str):
            normalized[key] = item
    return normalized


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def connection_args() -> list[str]:
    return [
        "--host",
        "firewall.example.com",
        "--username",
        "api-user",
        "--password",
        "super-secret",
    ]


@pytest.fixture
def firewall_client(monkeypatch: pytest.MonkeyPatch) -> InMemoryFirewallClient:
    client = InMemoryFirewallClient()

    def _create_client(_params: ConnectionParams) -> InMemoryFirewallClient:
        return client

    monkeypatch.setattr("sophos_cli.cli.create_client", _create_client)
    monkeypatch.setattr("sophos_cli.commands.dns.create_client", _create_client)
    return client
