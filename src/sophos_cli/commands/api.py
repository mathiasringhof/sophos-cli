"""Generated raw SDK command wrappers for Sophos Firewall methods."""

from __future__ import annotations

import inspect
import json
from dataclasses import dataclass
from types import UnionType
from typing import Any, Union, cast, get_args, get_origin

import typer
from click.core import ParameterSource
from rich.console import Console
from rich.json import JSON
from sophosfirewall_python.api_client import (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallInvalidArgument,
    SophosFirewallOperatorError,
    SophosFirewallZeroRecords,
)
from sophosfirewall_python.firewallapi import SophosFirewall

from sophos_cli.config import Settings
from sophos_cli.connection import (
    connection_params,
)
from sophos_cli.sdk import create_client

api_app = typer.Typer(
    help=(
        "Raw sophosfirewall-python SDK commands. "
        "List and dict parameters are passed as JSON using --<name>-json."
    )
)
console = Console()
API_EXCEPTIONS = (
    SophosFirewallAPIError,
    SophosFirewallAuthFailure,
    SophosFirewallInvalidArgument,
    SophosFirewallOperatorError,
    SophosFirewallZeroRecords,
)
_EMPTY = inspect.Signature.empty

@dataclass(frozen=True, slots=True)
class CliParamSpec:
    """Description of a generated CLI parameter for an SDK method."""

    method_name: str
    sdk_name: str
    cli_name: str
    annotation: Any
    default: object
    is_json: bool = False
    is_extra_json: bool = False


def _render(payload: Any) -> None:
    console.print(JSON.from_data(payload))


def _normalize_default(annotation: Any, default: object) -> object:
    if default is _EMPTY:
        return ...
    if annotation is str and default is dict:
        return "dict"
    return default


def _is_complex_annotation(annotation: Any) -> bool:
    if annotation is _EMPTY:
        return False

    origin = get_origin(annotation)
    if origin in (list, dict):
        return True
    if origin in (UnionType, Union):
        return any(_is_complex_annotation(arg) for arg in get_args(annotation) if arg is not type(None))
    return annotation in (list, dict)


def _option_help(spec: CliParamSpec) -> str:
    if spec.is_extra_json:
        return "JSON object merged into **kwargs for the SDK method."
    if spec.is_json:
        return f"JSON value for SDK parameter '{spec.sdk_name}'."
    return f"SDK parameter '{spec.sdk_name}'."


def _build_cli_param(method_name: str, parameter: inspect.Parameter) -> CliParamSpec:
    annotation = parameter.annotation
    if annotation is _EMPTY:
        if parameter.default not in (_EMPTY, None):
            annotation = cast(Any, type(parameter.default))
        else:
            annotation = str | None

    default = _normalize_default(annotation, parameter.default)

    if parameter.kind is inspect.Parameter.VAR_KEYWORD:
        return CliParamSpec(
            method_name=method_name,
            sdk_name=parameter.name,
            cli_name="extra_json",
            annotation=str | None,
            default=None,
            is_extra_json=True,
        )

    if _is_complex_annotation(annotation):
        required = parameter.default is _EMPTY
        return CliParamSpec(
            method_name=method_name,
            sdk_name=parameter.name,
            cli_name=f"{parameter.name}_json",
            annotation=str if required else str | None,
            default=... if required else None,
            is_json=True,
        )

    return CliParamSpec(
        method_name=method_name,
        sdk_name=parameter.name,
        cli_name=parameter.name,
        annotation=annotation,
        default=default,
    )


def _parameter_from_spec(spec: CliParamSpec) -> inspect.Parameter:
    option_name = (
        "--extra-json"
        if spec.is_extra_json
        else f"--{spec.sdk_name.replace('_', '-')}-json"
        if spec.is_json
        else f"--{spec.sdk_name.replace('_', '-')}"
    )
    return inspect.Parameter(
        spec.cli_name,
        inspect.Parameter.POSITIONAL_OR_KEYWORD,
        annotation=spec.annotation,
        default=typer.Option(spec.default, option_name, help=_option_help(spec)),
    )


def _coerce_json_parameter(spec: CliParamSpec, raw_value: str) -> Any:
    try:
        return json.loads(raw_value)
    except json.JSONDecodeError as exc:
        option_name = "--extra-json" if spec.is_extra_json else f"--{spec.sdk_name.replace('_', '-')}-json"
        raise typer.BadParameter(f"Invalid JSON for {option_name}: {exc.msg}") from exc


def _command_help(method_name: str, method: Any, specs: list[CliParamSpec]) -> str:
    base = inspect.getdoc(method) or f"Invoke SophosFirewall.{method_name}."
    if any(spec.is_json or spec.is_extra_json for spec in specs):
        return (
            f"{base}\n\n"
            "Complex list/dict parameters use JSON options such as --service-list-json. "
            "Methods with **kwargs also accept --extra-json."
        )
    return base


def _build_signature(specs: list[CliParamSpec]) -> inspect.Signature:
    parameters = [
        inspect.Parameter(
            "ctx",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=typer.Context,
        ),
        *[_parameter_from_spec(spec) for spec in specs],
        inspect.Parameter(
            "connection_host",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=str | None,
            default=typer.Option(None, "--host", help="Firewall hostname or IP."),
        ),
        inspect.Parameter(
            "connection_username",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=str | None,
            default=typer.Option(None, "--username", help="Firewall API username."),
        ),
        inspect.Parameter(
            "connection_password",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=str | None,
            default=typer.Option(None, "--password", help="Firewall API password."),
        ),
        inspect.Parameter(
            "connection_port",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=int | None,
            default=typer.Option(None, "--port", min=1, max=65535, help="Firewall API port."),
        ),
        inspect.Parameter(
            "connection_insecure",
            inspect.Parameter.POSITIONAL_OR_KEYWORD,
            annotation=bool,
            default=typer.Option(False, "--insecure", help="Disable TLS certificate verification."),
        ),
    ]
    return inspect.Signature(parameters)


def _invoke_generated_method(
    ctx: typer.Context,
    method_name: str,
    specs: list[CliParamSpec],
    **kwargs: Any,
) -> None:
    settings: Settings = ctx.obj["settings"]
    params = connection_params(
        settings,
        kwargs.pop("connection_host"),
        kwargs.pop("connection_username"),
        kwargs.pop("connection_password"),
        kwargs.pop("connection_port"),
        kwargs.pop("connection_insecure"),
    )

    call_kwargs: dict[str, Any] = {}
    for spec in specs:
        value = kwargs.pop(spec.cli_name, None)
        source = ctx.get_parameter_source(spec.cli_name)
        if value is None:
            continue
        if source is ParameterSource.DEFAULT and spec.default is not ...:
            continue
        if spec.is_extra_json:
            extra_kwargs = _coerce_json_parameter(spec, value)
            if not isinstance(extra_kwargs, dict):
                raise typer.BadParameter("--extra-json must decode to a JSON object.")
            call_kwargs.update(cast(dict[str, Any], extra_kwargs))
            continue
        if spec.is_json:
            call_kwargs[spec.sdk_name] = _coerce_json_parameter(spec, value)
            continue
        call_kwargs[spec.sdk_name] = value

    try:
        client = create_client(params)
        result = getattr(client, method_name)(**call_kwargs)
    except API_EXCEPTIONS as exc:
        console.print(f"API request failed: {exc}", style="bold red")
        raise typer.Exit(code=1) from exc

    _render(result)


def _register_sdk_command(method_name: str, method: Any) -> None:
    signature = inspect.signature(method)
    specs = [
        _build_cli_param(method_name, parameter)
        for parameter in signature.parameters.values()
        if parameter.name != "self"
    ]

    def _command(**kwargs: Any) -> None:
        ctx = kwargs.pop("ctx")
        _invoke_generated_method(ctx, method_name, specs, **kwargs)

    _command.__name__ = f"api_{method_name}"
    _command.__doc__ = _command_help(method_name, method, specs)
    cast(Any, _command).__signature__ = _build_signature(specs)
    api_app.command(method_name.replace("_", "-"))(_command)


for _method_name, _method in SophosFirewall.__dict__.items():
    if _method_name.startswith("_") or not inspect.isfunction(_method):
        continue
    _register_sdk_command(_method_name, _method)
