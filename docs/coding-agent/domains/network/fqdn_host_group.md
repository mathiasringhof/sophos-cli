# Network - FQDN Host Group

## Scope

- Domain: `network`
- Resource: `FQDNHostGroup`
- CLI path: `network fqdn-host-group`

## Supported Operations

| CLI Command | Behavior |
| --- | --- |
| `list` | List FQDN host groups |
| `get <name>` | Fetch one group by `Name` |
| `create <name> --host <member>...` | Create a host group with one or more FQDN hosts |
| `update <name> --host <member>... --action <add|remove|replace>` | Adjust group membership |
| `delete <name> --yes` | Remove the group |

## SDK Integration

- Read: `get_fqdn_hostgroup()`, `get_fqdn_hostgroup(name=...)`
- Create: `create_fqdn_hostgroup(...)`
- Update: `update_fqdn_hostgroup(...)`
- Delete: generic `remove(xml_tag="FQDNHostGroup", key="Name")`
