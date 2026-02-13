import pytest
import xmltodict
from sophosfirewall_python.api_client import SophosFirewallZeroRecords

from sophos_cli.models.dns import DnsHostAddress, DnsHostEntryCreate, DnsHostEntryUpdate
from sophos_cli.services.dns_service import DnsService


class FakeFirewallClient:
    def __init__(self) -> None:
        self.entries: dict[str, dict[str, object]] = {}

    def get_tag(self, xml_tag: str):
        assert xml_tag == "DNSHostEntry"
        if not self.entries:
            raise SophosFirewallZeroRecords("Number of records Zero.")

        values = list(self.entries.values())
        payload = values if len(values) > 1 else values[0]
        return {"Response": {"DNSHostEntry": payload}}

    def get_tag_with_filter(self, xml_tag: str, key: str, value: str, operator: str = "="):
        assert xml_tag == "DNSHostEntry"
        assert key == "HostName"
        assert operator == "="

        if value not in self.entries:
            raise SophosFirewallZeroRecords("Number of records Zero.")
        return {"Response": {"DNSHostEntry": self.entries[value]}}

    def submit_xml(self, template_data: str, set_operation: str = "add"):
        payload = xmltodict.parse(template_data)
        entry = payload["DNSHostEntry"]
        host_name = entry["HostName"]

        self.entries[host_name] = entry

        action = "Created" if set_operation == "add" else "Updated"
        return {"Response": {"DNSHostEntry": {"Status": {"@code": "200", "#text": action}}}}


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
    assert updated["AddressList"]["Address"]["IPAddress"] == "192.0.2.50"


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
