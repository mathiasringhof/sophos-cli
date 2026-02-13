from typing import cast

import pytest
import xmltodict
from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate
from sophos_cli.services.dns_service import DnsService


class FakeFirewallClient:
    def __init__(self) -> None:
        self.entries: dict[str, dict[str, object]] = {}

    def login(self, output_format: str = "dict") -> dict[str, object]:
        del output_format
        return {"Response": {"Status": {"@code": "200", "#text": "Authentication Successful"}}}

    def get_tag(
        self,
        xml_tag: str,
        timeout: int = 30,
        output_format: str = "dict",
    ) -> dict[str, object]:
        del timeout, output_format
        assert xml_tag == "DNSHostEntry"
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
        del timeout, output_format
        assert xml_tag == "DNSHostEntry"
        assert key == "HostName"
        assert operator == "="

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


def _sample_entry(host_name: str, ip_address: str) -> DnsHostEntryCreate:
    return DnsHostEntryCreate(
        host_name=host_name,
        addresses=[
            DnsHostAddress(
                entry_type="Manual",
                ip_family="IPv4",
                ip_address=ip_address,
                ttl=3600,
                weight=0,
                publish_on_wan="Disable",
            )
        ],
        add_reverse_dns_lookup=False,
    )


def test_add_entry_fails_when_exists_without_force() -> None:
    client = FakeFirewallClient()
    client.entries["web-1.example.com"] = {
        "HostName": "web-1.example.com",
        "AddressList": {
            "Address": {
                "EntryType": "Manual",
                "IPFamily": "IPv4",
                "IPAddress": "192.0.2.10",
                "TTL": "3600",
                "Weight": "0",
                "PublishOnWAN": "Disable",
            }
        },
        "AddReverseDNSLookUp": "Disable",
    }
    service = DnsService(client)

    with pytest.raises(ValueError):
        service.add_entry(_sample_entry("web-1.example.com", "192.0.2.20"), force=False)


def test_add_entry_with_force_updates_existing() -> None:
    client = FakeFirewallClient()
    client.entries["web-1.example.com"] = {
        "HostName": "web-1.example.com",
        "AddressList": {
            "Address": {
                "EntryType": "Manual",
                "IPFamily": "IPv4",
                "IPAddress": "192.0.2.10",
                "TTL": "3600",
                "Weight": "0",
                "PublishOnWAN": "Disable",
            }
        },
        "AddReverseDNSLookUp": "Disable",
    }
    service = DnsService(client)

    action, _ = service.add_entry(_sample_entry("web-1.example.com", "192.0.2.50"), force=True)

    assert action == "updated"
    updated = client.entries["web-1.example.com"]
    address_list = cast(dict[str, object], updated["AddressList"])
    address = cast(dict[str, object], address_list["Address"])
    assert address["IPAddress"] == "192.0.2.50"


def test_update_entry_fails_when_missing() -> None:
    service = DnsService(FakeFirewallClient())

    with pytest.raises(ValueError):
        service.update_entry(
            DnsHostEntryUpdate(
                host_name="missing.example.com",
                addresses=[
                    DnsHostAddress(
                        entry_type="Manual",
                        ip_family="IPv4",
                        ip_address="192.0.2.33",
                    )
                ],
            )
        )


def test_list_entries_returns_normalized_models() -> None:
    client = FakeFirewallClient()
    client.entries = {
        "web-1.example.com": {
            "HostName": "web-1.example.com",
            "AddressList": {
                "Address": {
                    "EntryType": "Manual",
                    "IPFamily": "IPv4",
                    "IPAddress": "192.0.2.10",
                    "TTL": "3600",
                    "Weight": "0",
                    "PublishOnWAN": "Disable",
                }
            },
            "AddReverseDNSLookUp": "Disable",
        },
        "api-1.example.com": {
            "HostName": "api-1.example.com",
            "AddressList": {
                "Address": {
                    "EntryType": "Manual",
                    "IPFamily": "IPv4",
                    "IPAddress": "192.0.2.20",
                    "TTL": "3600",
                    "Weight": "10",
                    "PublishOnWAN": "Enable",
                }
            },
            "AddReverseDNSLookUp": "Enable",
        },
    }
    service = DnsService(client)

    entries = service.list_entries()

    assert len(entries) == 2
    assert {entry.host_name for entry in entries} == {
        "web-1.example.com",
        "api-1.example.com",
    }


def test_list_entries_accepts_single_label_hostname() -> None:
    client = FakeFirewallClient()
    client.entries = {
        "unifi": {
            "HostName": "unifi",
            "AddressList": {
                "Address": {
                    "EntryType": "Manual",
                    "IPFamily": "IPv4",
                    "IPAddress": "192.0.2.99",
                    "TTL": "3600",
                    "Weight": "0",
                    "PublishOnWAN": "Disable",
                }
            },
            "AddReverseDNSLookUp": "Disable",
        }
    }
    service = DnsService(client)

    entries = service.list_entries()

    assert len(entries) == 1
    assert entries[0].host_name == "unifi"


def test_add_many_returns_failure_summary() -> None:
    client = FakeFirewallClient()
    client.entries["web-1.example.com"] = {
        "HostName": "web-1.example.com",
        "AddressList": {
            "Address": {
                "EntryType": "Manual",
                "IPFamily": "IPv4",
                "IPAddress": "192.0.2.10",
                "TTL": "3600",
                "Weight": "0",
                "PublishOnWAN": "Disable",
            }
        },
        "AddReverseDNSLookUp": "Disable",
    }
    service = DnsService(client)

    result = service.add_many(
        [
            _sample_entry("web-1.example.com", "192.0.2.30"),
            _sample_entry("api-1.example.com", "192.0.2.40"),
        ],
        force=False,
        continue_on_error=True,
    )

    assert result.total == 2
    assert result.created == 1
    assert result.failed == 1
