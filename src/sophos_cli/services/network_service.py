"""Service layer for Wave 1 network resources."""

from __future__ import annotations

from typing import Any

from sophos_cli.command_support import normalize_object_dict, response_records
from sophos_cli.firewall_client import FirewallClientProtocol, FirewallObject
from sophos_cli.models.network import (
    FqdnHostCreate,
    FqdnHostGroupCreate,
    FqdnHostGroupUpdate,
    FqdnHostUpdate,
    IpHostCreate,
    IpHostGroupCreate,
    IpHostGroupUpdate,
    IpHostUpdate,
    IpNetworkCreate,
    IpNetworkUpdate,
    IpRangeCreate,
    IpRangeUpdate,
)


class NetworkService:
    """Service wrapper for explicit network object commands."""

    def __init__(self, client: FirewallClientProtocol):
        self._client = client

    def list_ip_hosts(self) -> list[FirewallObject]:
        return response_records(self._client.get_ip_host(), "IPHost")

    def get_ip_host(self, name: str) -> FirewallObject | None:
        records = response_records(self._client.get_ip_host(name=name), "IPHost")
        return records[0] if records else None

    def create_ip_host(self, payload: IpHostCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_ip_host(name=payload.name, ip_address=payload.ip_address)
        )

    def update_ip_host(self, payload: IpHostUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update(
                xml_tag="IPHost",
                name=payload.name,
                lookup_key="Name",
                update_params={
                    "HostType": "IP",
                    "IPFamily": "IPv4",
                    "IPAddress": payload.ip_address,
                },
            )
        )

    def delete_ip_host(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="IPHost", name=name, key="Name"))

    def list_ip_networks(self) -> list[FirewallObject]:
        return [record for record in self.list_ip_hosts() if record.get("HostType") == "Network"]

    def get_ip_network(self, name: str) -> FirewallObject | None:
        record = self.get_ip_host(name)
        return record if record and record.get("HostType") == "Network" else None

    def create_ip_network(self, payload: IpNetworkCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_ip_network(
                name=payload.name,
                ip_network=payload.ip_network,
                mask=payload.mask,
            )
        )

    def update_ip_network(self, payload: IpNetworkUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update(
                xml_tag="IPHost",
                name=payload.name,
                lookup_key="Name",
                update_params={
                    "HostType": "Network",
                    "IPFamily": "IPv4",
                    "IPAddress": payload.ip_network,
                    "Subnet": payload.mask,
                },
            )
        )

    def delete_ip_network(self, name: str) -> FirewallObject:
        return self.delete_ip_host(name)

    def list_ip_ranges(self) -> list[FirewallObject]:
        return [record for record in self.list_ip_hosts() if record.get("HostType") == "IPRange"]

    def get_ip_range(self, name: str) -> FirewallObject | None:
        record = self.get_ip_host(name)
        return record if record and record.get("HostType") == "IPRange" else None

    def create_ip_range(self, payload: IpRangeCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_ip_range(
                name=payload.name,
                start_ip=payload.start_ip,
                end_ip=payload.end_ip,
            )
        )

    def update_ip_range(self, payload: IpRangeUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update(
                xml_tag="IPHost",
                name=payload.name,
                lookup_key="Name",
                update_params={
                    "HostType": "IPRange",
                    "IPFamily": "IPv4",
                    "StartIPAddress": payload.start_ip,
                    "EndIPAddress": payload.end_ip,
                },
            )
        )

    def delete_ip_range(self, name: str) -> FirewallObject:
        return self.delete_ip_host(name)

    def list_ip_host_groups(self) -> list[FirewallObject]:
        return response_records(self._client.get_ip_hostgroup(), "IPHostGroup")

    def get_ip_host_group(self, name: str) -> FirewallObject | None:
        records = response_records(self._client.get_ip_hostgroup(name=name), "IPHostGroup")
        return records[0] if records else None

    def create_ip_host_group(self, payload: IpHostGroupCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_ip_hostgroup(
                name=payload.name,
                host_list=payload.host_list,
                description=payload.description,
            )
        )

    def update_ip_host_group(self, payload: IpHostGroupUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_ip_hostgroup(
                name=payload.name,
                host_list=payload.host_list,
                description=payload.description,
                action=payload.action,
            )
        )

    def delete_ip_host_group(self, name: str) -> FirewallObject:
        return normalize_object_dict(
            self._client.remove(xml_tag="IPHostGroup", name=name, key="Name")
        )

    def list_fqdn_hosts(self) -> list[FirewallObject]:
        return response_records(self._client.get_fqdn_host(), "FQDNHost")

    def get_fqdn_host(self, name: str) -> FirewallObject | None:
        records = response_records(self._client.get_fqdn_host(name=name), "FQDNHost")
        return records[0] if records else None

    def create_fqdn_host(self, payload: FqdnHostCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_fqdn_host(
                name=payload.name,
                fqdn=payload.fqdn,
                fqdn_group_list=payload.fqdn_group_list,
                description=payload.description,
            )
        )

    def update_fqdn_host(self, payload: FqdnHostUpdate) -> FirewallObject:
        update_params: dict[str, Any] = {"FQDN": payload.fqdn}
        if payload.description is not None:
            update_params["Description"] = payload.description
        if payload.fqdn_group_list:
            update_params["FQDNHostGroupList"] = {"FQDNHostGroup": payload.fqdn_group_list}
        return normalize_object_dict(
            self._client.update(
                xml_tag="FQDNHost",
                name=payload.name,
                lookup_key="Name",
                update_params=update_params,
            )
        )

    def delete_fqdn_host(self, name: str) -> FirewallObject:
        return normalize_object_dict(self._client.remove(xml_tag="FQDNHost", name=name, key="Name"))

    def list_fqdn_host_groups(self) -> list[FirewallObject]:
        return response_records(self._client.get_fqdn_hostgroup(), "FQDNHostGroup")

    def get_fqdn_host_group(self, name: str) -> FirewallObject | None:
        records = response_records(self._client.get_fqdn_hostgroup(name=name), "FQDNHostGroup")
        return records[0] if records else None

    def create_fqdn_host_group(self, payload: FqdnHostGroupCreate) -> FirewallObject:
        return normalize_object_dict(
            self._client.create_fqdn_hostgroup(
                name=payload.name,
                fqdn_host_list=payload.fqdn_host_list,
                description=payload.description,
            )
        )

    def update_fqdn_host_group(self, payload: FqdnHostGroupUpdate) -> FirewallObject:
        return normalize_object_dict(
            self._client.update_fqdn_hostgroup(
                name=payload.name,
                fqdn_host_list=payload.fqdn_host_list,
                description=payload.description,
                action=payload.action,
            )
        )

    def delete_fqdn_host_group(self, name: str) -> FirewallObject:
        return normalize_object_dict(
            self._client.remove(xml_tag="FQDNHostGroup", name=name, key="Name")
        )
