# DNS - DNS Host Entry (RAW XML API)

## Scope

- Domain: `dns`
- Resource: `DNSHostEntry`
- Operations covered by the source API doc: `Add DNS Host Entry`, `Edit DNS Host Entry`
- Purpose: map host/domain names to IPv4/IPv6 targets with optional WAN publishing and reverse lookup.

## Operation Matrix

| Operation | XML Tag | SDK Call Pattern | Idempotency Strategy |
| --- | --- | --- | --- |
| Add | `DNSHostEntry` | Create request for full object payload | Fail on duplicate name unless explicit upsert mode |
| Edit | `DNSHostEntry` | Update request keyed by `HostName` | Fail if entry does not exist |

## XML Payload Shape

```xml
<DNSHostEntry>
  <HostName>host.example.com</HostName>
  <AddressList>
    <!-- max 8 addresses -->
    <Address>
      <EntryType>Manual</EntryType>
      <IPFamily>IPv4</IPFamily>
      <IPAddress>192.0.2.10</IPAddress>
      <TTL>3600</TTL>
      <Weight>10</Weight>
      <PublishOnWAN>Disable</PublishOnWAN>
    </Address>
  </AddressList>
  <AddReverseDNSLookUp>Enable</AddReverseDNSLookUp>
</DNSHostEntry>
```

## Field Rules

| Field | Required | Default | Allowed Values / Range | Notes |
| --- | --- | --- | --- | --- |
| `HostName` | Yes | None | FQDN, max 253 chars | Scalar |
| `AddressList` | Yes | None | 1 to 8 `Address` entries | Maximum 8 addresses |
| `Address.EntryType` | Yes | None | `Manual`, `InterfaceIP` | Per address |
| `Address.IPFamily` | Yes | None | `IPv4`, `IPv6` | Per address |
| `Address.IPAddress` | Yes | None | String IP/interface value | Interface name is required when `EntryType=InterfaceIP` (per source text) |
| `Address.TTL` | Yes | `3600` | Integer `1..604800` | Seconds |
| `Address.Weight` | Yes | None | Integer `0..255` | Load balancing weight |
| `Address.PublishOnWAN` | Yes | None | `Enable`, `Disable` | Per address |
| `AddReverseDNSLookUp` | No | `Disable` | `Enable` (only listed allowed value) | Treat omission as disabled |

## Validation Rules For CLI Models

Recommended model split:

- `DnsHostAddress`
- `DnsHostEntryCreate`
- `DnsHostEntryUpdate`

Validation to enforce before SDK call:

- `hostname` must be valid FQDN and length <= 253.
- `addresses` length must be `1..8`.
- `ip_family` must match `IPv4`/`IPv6`.
- For `entry_type=Manual`, `ip_address` must be a valid unicast address for the selected family.
- For `entry_type=InterfaceIP`, require interface identifier input (exact field/value behavior should be verified against live API).
- `ttl` must be `1..604800`.
- `weight` must be `0..255`.
- `publish_on_wan` must be `Enable|Disable`.
- Reject reserved IP classes listed as disallowed by source doc (`MULTICAST`, `RESERVED`, `UNSPECIFIED`, `BROADCAST`, `LINKLOCAL`).

## Status/Response Mapping

| Operation | Code | Meaning | CLI Behavior |
| --- | --- | --- | --- |
| Add/Edit | `200` | Success | Print success summary + API payload |
| Add/Edit | `500` | Missing/invalid host, TTL, or IP params | Exit `1`, show validation error |
| Add | `502` | Host/domain already exists | Exit `1`, suggest `--force`/update flow |
| Edit | `502` | Generic update failure ("Contact support") | Exit `1`, include raw message |
| Add/Edit | `503` | Identical configuration already exists | Treat as conflict/no-op based on command semantics |
| Add | `510` | Max 1024 DNS host entries reached | Exit `1`, actionable limit message |
| Add | `541` | Generic support error | Exit `1`, include escalation hint |

## SDK Integration Pattern

Preferred implementation style in this repository:

1. Build Pydantic model instances from CLI input.
2. Convert models into XML-compatible payload dictionaries.
3. Use SDK methods for create/get/update:
   - Use tag-level get for list/read (`get_tag` / filtered get).
   - Use update by lookup key for edit.
   - For create, use a dedicated SDK helper if available; otherwise use the SDK generic create path for `DNSHostEntry`.
4. Normalize list/single-object API responses in service layer before returning command output.

## Examples

### Minimal Add Payload (Manual IPv4)

```xml
<DNSHostEntry>
  <HostName>app1.example.com</HostName>
  <AddressList>
    <Address>
      <EntryType>Manual</EntryType>
      <IPFamily>IPv4</IPFamily>
      <IPAddress>192.0.2.10</IPAddress>
      <TTL>3600</TTL>
      <Weight>0</Weight>
      <PublishOnWAN>Disable</PublishOnWAN>
    </Address>
  </AddressList>
</DNSHostEntry>
```

### Representative CLI JSON Input

```json
{
  "hostname": "app1.example.com",
  "addresses": [
    {
      "entry_type": "Manual",
      "ip_family": "IPv4",
      "ip_address": "192.0.2.10",
      "ttl": 3600,
      "weight": 0,
      "publish_on_wan": "Disable"
    }
  ],
  "add_reverse_dns_lookup": false
}
```

## Testing Guidance

- Model tests:
  - hostname validation
  - address count limit (`>8` rejected)
  - TTL/weight range enforcement
  - entry-type-specific address validation
- Service tests:
  - add/update status code mapping
  - parsing list vs single response payloads
  - duplicate handling (`502` and `503`)
- CLI tests:
  - required-field failures
  - successful add/edit output
  - clear errors for max-entry and invalid-input cases

## Open Questions / Unknowns

- Confirm exact SDK create method for `DNSHostEntry` in `sophosfirewall-python`.
- Confirm precise field/value expected for `InterfaceIP` mode (`IPAddress` vs separate interface field).
- Confirm whether `AddReverseDNSLookUp=Disable` is accepted explicitly or must be omitted.
