# Network - FQDN Host

## Scope

- Domain: `network`
- Resource: `FQDNHost`
- CLI path: `network fqdn-host`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List FQDN host objects |
| `get <name>` | Fetch one object by `Name` |
| `create <name> --fqdn <fqdn> [--group <group>...]` | Create an FQDN host |
| `update <name> --fqdn <fqdn> [--group <group>...]` | Update FQDN, description, and group associations |
| `delete <name> --yes` | Remove the object |

## SDK Integration

- Read: `get_fqdn_host()`, `get_fqdn_host(name=...)`
- Create: `create_fqdn_host(...)`
- Update: generic `update(xml_tag="FQDNHost", lookup_key="Name", ...)`
- Delete: generic `remove(xml_tag="FQDNHost", key="Name")`
