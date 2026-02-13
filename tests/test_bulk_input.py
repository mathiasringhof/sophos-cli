from io import StringIO

import pytest

from sophos_cli.io.bulk_input import load_dns_add_entries, load_dns_update_entries


def test_load_dns_add_entries_from_json_file(tmp_path) -> None:
    source = tmp_path / "entries.json"
    source.write_text(
        (
            '[{"host_name": "web-1.example.com", '
            '"addresses": [{"ip_address": "192.0.2.10", "ip_family": "IPv4"}]}]'
        ),
        encoding="utf-8",
    )

    entries = load_dns_add_entries(str(source))

    assert len(entries) == 1
    assert entries[0].host_name == "web-1.example.com"
    assert entries[0].addresses[0].ip_address == "192.0.2.10"


def test_load_dns_update_entries_from_csv_file(tmp_path) -> None:
    source = tmp_path / "entries.csv"
    source.write_text(
        "host_name,ip_address,ip_family,ttl,weight,publish_on_wan\n"
        "web-1.example.com,192.0.2.11,IPv4,60,5,Enable\n",
        encoding="utf-8",
    )

    entries = load_dns_update_entries(str(source))

    assert len(entries) == 1
    assert entries[0].host_name == "web-1.example.com"
    assert entries[0].addresses is not None
    assert entries[0].addresses[0].ttl == 60
    assert entries[0].addresses[0].publish_on_wan == "Enable"


def test_load_dns_add_entries_from_stdin(monkeypatch) -> None:
    monkeypatch.setattr(
        "sys.stdin",
        StringIO(
            '[{"host_name": "api-1.example.com", "addresses": '
            '[{"ip_address": "192.0.2.20", "ip_family": "IPv4"}]}]'
        ),
    )

    entries = load_dns_add_entries("-")

    assert len(entries) == 1
    assert entries[0].host_name == "api-1.example.com"


def test_update_entries_require_mutation_field(tmp_path) -> None:
    source = tmp_path / "entries.json"
    source.write_text('[{"host_name": "web-1.example.com"}]', encoding="utf-8")

    with pytest.raises(ValueError):
        load_dns_update_entries(str(source))
