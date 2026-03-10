"""Typed protocol for firewall client interactions used by services/commands."""

from __future__ import annotations

from typing import Protocol

type FirewallObject = dict[str, object]


class FirewallClientProtocol(Protocol):
    """Subset of SDK methods used by this project."""

    def login(self, output_format: str = "dict") -> object: ...

    def get_tag(
        self,
        xml_tag: str,
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def get_tag_with_filter(
        self,
        xml_tag: str,
        key: str,
        value: str,
        operator: str = "like",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def submit_xml(
        self,
        template_data: str,
        template_vars: dict[str, object] | None = None,
        set_operation: str = "add",
        timeout: int = 30,
        debug: bool = False,
    ) -> object: ...

    def remove(
        self,
        xml_tag: str,
        name: str,
        key: str = "Name",
        timeout: int = 30,
        output_format: str = "dict",
    ) -> object: ...

    def update(
        self,
        xml_tag: str,
        update_params: dict[str, object],
        name: str | None = None,
        lookup_key: str = "Name",
        output_format: str = "dict",
        timeout: int = 30,
        debug: bool = False,
    ) -> object: ...

    def get_ip_host(
        self,
        name: str | None = None,
        ip_address: str | None = None,
        operator: str = "=",
    ) -> object: ...

    def create_ip_host(
        self,
        name: str,
        ip_address: str | None = None,
        mask: str | None = None,
        start_ip: str | None = None,
        end_ip: str | None = None,
        host_type: str = "IP",
        debug: bool = False,
    ) -> object: ...

    def get_ip_hostgroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_ip_hostgroup(
        self,
        name: str,
        host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> object: ...

    def create_ip_network(
        self,
        name: str,
        ip_network: str,
        mask: str,
        debug: bool = False,
    ) -> object: ...

    def create_ip_range(
        self,
        name: str,
        start_ip: str,
        end_ip: str,
        debug: bool = False,
    ) -> object: ...

    def get_fqdn_host(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_fqdn_host(
        self,
        name: str,
        fqdn: str,
        fqdn_group_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def get_fqdn_hostgroup(self, name: str | None = None, operator: str = "=") -> object: ...

    def create_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str] | None = None,
        description: str | None = None,
        debug: bool = False,
    ) -> object: ...

    def update_fqdn_hostgroup(
        self,
        name: str,
        fqdn_host_list: list[str],
        description: str | None = None,
        action: str = "add",
        debug: bool = False,
    ) -> object: ...
