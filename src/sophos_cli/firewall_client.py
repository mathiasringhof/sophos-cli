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
