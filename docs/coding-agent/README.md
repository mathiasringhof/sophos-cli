# Coding Agent API Documentation

This folder contains implementation-focused API documentation for `sophos-cli`.
It is optimized for coding agents and contributors who need a consistent structure
for modeling firewall resources in code.

## Goals

- Keep resource behavior (schema, validation, status handling) in one place.
- Make it easy to add new resource docs (DNS, DHCP, firewall rules, and more).
- Keep docs aligned with code design: models -> services -> commands.

## Structure

```text
docs/coding-agent/
  README.md
  templates/
    domain_resource_template.md
  domains/
    dns/
      dns_host_entry.md
    dhcp/
      # future resources
    firewall/
      # future resources
```

## Required Sections For Each Resource Doc

Every resource file under `domains/<domain>/` should follow the same section order:

1. `Scope`
2. `Operation Matrix`
3. `XML Payload Shape`
4. `Field Rules`
5. `Validation Rules For CLI Models`
6. `Status/Response Mapping`
7. `SDK Integration Pattern`
8. `Examples`
9. `Testing Guidance`
10. `Open Questions / Unknowns`

Use `templates/domain_resource_template.md` when adding new resources.

## Naming Conventions

- Domain folder: lowercase (`dns`, `dhcp`, `firewall`)
- Resource file: lowercase snake case (`dns_host_entry.md`)
- Keep one resource per file to avoid mixed concerns.

## Change Process

When adding support for a new API resource:

1. Add or update the resource doc.
2. Implement/extend model(s) in `src/sophos_cli/models/`.
3. Implement service logic in `src/sophos_cli/services/`.
4. Wire CLI commands in `src/sophos_cli/commands/`.
5. Add/update tests under `tests/`.

## Current Coverage

- Support matrix: `docs/coding-agent/support_matrix.md`
- DNS: `docs/coding-agent/domains/dns/dns_host_entry.md`
- Network:
  - `docs/coding-agent/domains/network/ip_host.md`
  - `docs/coding-agent/domains/network/ip_host_group.md`
  - `docs/coding-agent/domains/network/ip_network.md`
  - `docs/coding-agent/domains/network/ip_range.md`
  - `docs/coding-agent/domains/network/fqdn_host.md`
  - `docs/coding-agent/domains/network/fqdn_host_group.md`
