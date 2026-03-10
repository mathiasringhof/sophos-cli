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
        self.ip_hosts: dict[str, dict[str, object]] = {}
        self.ip_host_groups: dict[str, dict[str, object]] = {}
        self.fqdn_hosts: dict[str, dict[str, object]] = {}
        self.fqdn_host_groups: dict[str, dict[str, object]] = {}
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
            if xml_tag == "IPHost":
                if not self.ip_hosts:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                values = list(self.ip_hosts.values())
                payload: object = values if len(values) > 1 else values[0]
                return {"Response": {"IPHost": payload}}
            if xml_tag == "IPHostGroup":
                if not self.ip_host_groups:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                values = list(self.ip_host_groups.values())
                payload = values if len(values) > 1 else values[0]
                return {"Response": {"IPHostGroup": payload}}
            if xml_tag == "FQDNHost":
                if not self.fqdn_hosts:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                values = list(self.fqdn_hosts.values())
                payload = values if len(values) > 1 else values[0]
                return {"Response": {"FQDNHost": payload}}
            if xml_tag == "FQDNHostGroup":
                if not self.fqdn_host_groups:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                values = list(self.fqdn_host_groups.values())
                payload = values if len(values) > 1 else values[0]
                return {"Response": {"FQDNHostGroup": payload}}
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
            if xml_tag == "IPHost":
                if value not in self.ip_hosts:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                return {"Response": {"IPHost": self.ip_hosts[value]}}
            if xml_tag == "IPHostGroup":
                if value not in self.ip_host_groups:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                return {"Response": {"IPHostGroup": self.ip_host_groups[value]}}
            if xml_tag == "FQDNHost":
                if value not in self.fqdn_hosts:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                return {"Response": {"FQDNHost": self.fqdn_hosts[value]}}
            if xml_tag == "FQDNHostGroup":
                if value not in self.fqdn_host_groups:
                    raise SophosFirewallZeroRecords("Number of records Zero.")
                return {"Response": {"FQDNHostGroup": self.fqdn_host_groups[value]}}
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

    def remove(
        self,
        xml_tag: str,
        name: str,
        key: str = "Name",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> dict[str, object]:
        del key, timeout, output_format
        self.last_call = ("remove", {"xml_tag": xml_tag, "name": name})
        store = {
            "DNSHostEntry": self.entries,
            "IPHost": self.ip_hosts,
            "IPHostGroup": self.ip_host_groups,
            "FQDNHost": self.fqdn_hosts,
            "FQDNHostGroup": self.fqdn_host_groups,
        }[xml_tag]
        store.pop(name, None)
        return {"Response": {"Status": {"@code": "200", "#text": f"Deleted {xml_tag}"}}}

    def update(
        self,
        xml_tag: str,
        update_params: dict[str, object],
        name: str | None = None,
        lookup_key: str = "Name",
        output_format: str = "dict",
        timeout: int = 30,
        debug: bool = False,
    ) -> dict[str, object]:
        del lookup_key, output_format, timeout, debug
        assert name is not None
        self.last_call = ("update", {"xml_tag": xml_tag, "name": name, "update_params": update_params})
        if xml_tag == "IPHost":
            current = self.ip_hosts.get(name, {"Name": name})
            merged = {**current, **update_params, "Name": name}
            self.ip_hosts[name] = merged
            return {"Response": {"IPHost": merged}}
        if xml_tag == "FQDNHost":
            current = self.fqdn_hosts.get(name, {"Name": name})
            merged = {**current, **update_params, "Name": name}
            self.fqdn_hosts[name] = merged
            return {"Response": {"FQDNHost": merged}}
        return {"Response": {xml_tag: {"Name": name, **update_params}}}

    def get_ip_host(
        self,
        name: str | None = None,
        ip_address: str | None = None,
        operator: str = "=",
    ) -> dict[str, object]:
        del operator
        self.last_call = ("get_ip_host", {"name": name, "ip_address": ip_address})
        if name:
            if name not in self.ip_hosts:
                raise SophosFirewallZeroRecords("Number of records Zero.")
            return {"Response": {"IPHost": self.ip_hosts[name]}}
        if ip_address:
            for record in self.ip_hosts.values():
                if record.get("IPAddress") == ip_address:
                    return {"Response": {"IPHost": record}}
            raise SophosFirewallZeroRecords("Number of records Zero.")
        if not self.ip_hosts:
            raise SophosFirewallZeroRecords("Number of records Zero.")
        values = list(self.ip_hosts.values())
        payload: object = values if len(values) > 1 else values[0]
        return {"Response": {"IPHost": payload}}

    def create_ip_host(
        self,
        name: str,
        ip_address: str | None = None,
        mask: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        host_type: str = "IP",
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        record: dict[str, object] = {"Name": name, "HostType": host_type, "IPFamily": "IPv4"}
        if host_type == "IP":
            record["IPAddress"] = ip_address or ""
        elif host_type == "Network":
            record["IPAddress"] = ip_address or ""
            record["Subnet"] = mask or ""
        elif host_type == "IPRange":
            record["StartIPAddress"] = start_ip or ""
            record["EndIPAddress"] = end_ip or ""
        self.ip_hosts[name] = record
        self.last_call = ("create_ip_host", record.copy())
        return {"Response": {"IPHost": record}}

    def get_ip_hostgroup(self, name: str | None = None, operator: str = "=") -> dict[str, object]:
        del operator
        self.last_call = ("get_ip_hostgroup", {"name": name})
        if name:
            if name not in self.ip_host_groups:
                raise SophosFirewallZeroRecords("Number of records Zero.")
            return {"Response": {"IPHostGroup": self.ip_host_groups[name]}}
        if not self.ip_host_groups:
            raise SophosFirewallZeroRecords("Number of records Zero.")
        values = list(self.ip_host_groups.values())
        payload: object = values if len(values) > 1 else values[0]
        return {"Response": {"IPHostGroup": payload}}

    def create_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        record: dict[str, object] = {
            "Name": name,
            "Description": description or "",
            "HostList": {"Host": host_list},
        }
        self.ip_host_groups[name] = record
        self.last_call = ("create_ip_hostgroup", record.copy())
        return {"Response": {"IPHostGroup": record}}

    def update_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        current = self.ip_host_groups.get(name, {"Name": name, "HostList": {"Host": []}, "Description": ""})
        host_list_container = cast(dict[str, object], current.get("HostList", {"Host": []}))
        existing = host_list_container.get("Host", [])
        existing_list = [existing] if isinstance(existing, str) else list(cast(list[str], existing))
        new_list = [] if action == "replace" else existing_list
        for item in host_list:
            if action == "add" and item not in new_list:
                new_list.append(item)
            elif action == "remove" and item in new_list:
                new_list.remove(item)
            elif action == "replace":
                new_list.append(item)
        record = {
            "Name": name,
            "Description": description if description is not None else current.get("Description", ""),
            "HostList": {"Host": new_list},
        }
        self.ip_host_groups[name] = record
        self.last_call = ("update_ip_hostgroup", {"name": name, "action": action, "host_list": host_list})
        return {"Response": {"IPHostGroup": record}}

    def create_ip_network(
        self,
        name: str,
        ip_network: str,
        mask: str,
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        return self.create_ip_host(name=name, ip_address=ip_network, mask=mask, host_type="Network")

    def create_ip_range(
        self,
        name: str,
        start_ip: str,
        end_ip: str,
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        return self.create_ip_host(name=name, start_ip=start_ip, end_ip=end_ip, host_type="IPRange")

    def get_fqdn_host(self, name: str | None = None, operator: str = "=") -> dict[str, object]:
        del operator
        self.last_call = ("get_fqdn_host", {"name": name})
        if name:
            if name not in self.fqdn_hosts:
                raise SophosFirewallZeroRecords("Number of records Zero.")
            return {"Response": {"FQDNHost": self.fqdn_hosts[name]}}
        if not self.fqdn_hosts:
            raise SophosFirewallZeroRecords("Number of records Zero.")
        values = list(self.fqdn_hosts.values())
        payload: object = values if len(values) > 1 else values[0]
        return {"Response": {"FQDNHost": payload}}

    def create_fqdn_host(
        self,
        name: str,
        fqdn: str,
        fqdn_group_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        record: dict[str, object] = {
            "Name": name,
            "FQDN": fqdn,
            "Description": description or "",
            "FQDNHostGroupList": {"FQDNHostGroup": fqdn_group_list or []},
        }
        self.fqdn_hosts[name] = record
        self.last_call = ("create_fqdn_host", record.copy())
        return {"Response": {"FQDNHost": record}}

    def get_fqdn_hostgroup(self, name: str | None = None, operator: str = "=") -> dict[str, object]:
        del operator
        self.last_call = ("get_fqdn_hostgroup", {"name": name})
        if name:
            if name not in self.fqdn_host_groups:
                raise SophosFirewallZeroRecords("Number of records Zero.")
            return {"Response": {"FQDNHostGroup": self.fqdn_host_groups[name]}}
        if not self.fqdn_host_groups:
            raise SophosFirewallZeroRecords("Number of records Zero.")
        values = list(self.fqdn_host_groups.values())
        payload: object = values if len(values) > 1 else values[0]
        return {"Response": {"FQDNHostGroup": payload}}

    def create_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        record: dict[str, object] = {
            "Name": name,
            "Description": description or "",
            "FQDNHostList": {"FQDNHost": fqdn_host_list or []},
        }
        self.fqdn_host_groups[name] = record
        self.last_call = ("create_fqdn_hostgroup", record.copy())
        return {"Response": {"FQDNHostGroup": record}}

    def update_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> dict[str, object]:
        del debug
        current = self.fqdn_host_groups.get(name, {"Name": name, "Description": "", "FQDNHostList": {"FQDNHost": []}})
        fqdn_list_container = cast(dict[str, object], current.get("FQDNHostList", {"FQDNHost": []}))
        existing = fqdn_list_container.get("FQDNHost", [])
        existing_list = [existing] if isinstance(existing, str) else list(cast(list[str], existing))
        new_list = [] if action == "replace" else existing_list
        for item in fqdn_host_list:
            if action == "add" and item not in new_list:
                new_list.append(item)
            elif action == "remove" and item in new_list:
                new_list.remove(item)
            elif action == "replace":
                new_list.append(item)
        record = {
            "Name": name,
            "Description": description if description is not None else current.get("Description", ""),
            "FQDNHostList": {"FQDNHost": new_list},
        }
        self.fqdn_host_groups[name] = record
        self.last_call = ("update_fqdn_hostgroup", {"name": name, "action": action, "fqdn_host_list": fqdn_host_list})
        return {"Response": {"FQDNHostGroup": record}}


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

    monkeypatch.setattr("sophos_cli.command_support.create_client", _create_client)
    return client
