# AD CS certificate inventory (.NET)

Collect issued certificates from a two-tier AD CS hierarchy (offline root, two or more issuing CAs). The CA inventory is the base. For each valid certificate, the common name and every DNS or IP SAN is a client of that serial. Several clients may use the same certificate. That is not a conflict.

The collector probes each client on the local network and records the last-5-minute status: active, inactive, not in DNS, or not on the network. `--serve` then hosts the on-prem dashboard on this machine, next to that JSON file. The page only reads the inventory from the same host. It does not resolve names and it does not use the internet.

Live collection runs on a workstation that can reach every issuing CA and has the Certification Authority tools installed (`certadm.dll`, RSAT: AD CS). `--demo` and `--self-test` do not contact a CA.

The offline root is recorded by name only. End-entity rows come from the issuing CAs.

PowerShell port: [adcs_cert_inventory-powershell](https://github.com/nwlterry/adcs_cert_inventory-powershell).

The console can also run as a container on the isolated network. The container only serves the JSON this program writes. It does not contact a CA. [adcs_cert_inventory-container](https://github.com/nwlterry/adcs_cert_inventory-container).

## Collect

```powershell
dotnet run --project src/CertInventory -- --issuing-ca 'pki-ica01.corp.local\CORP-ISSUING-CA-01' --issuing-ca 'pki-ica02.corp.local\CORP-ISSUING-CA-02' --root-ca-name 'CORP-OFFLINE-ROOT-CA' --serve
```

After `dotnet publish -c Release -r win-x64 --self-contained false`:

```powershell
.\CertInventory.exe --issuing-ca 'pki-ica01.corp.local\CORP-ISSUING-CA-01' --issuing-ca 'pki-ica02.corp.local\CORP-ISSUING-CA-02' --root-ca-name 'CORP-OFFLINE-ROOT-CA' --serve
```

Open `http://127.0.0.1:8787/` on that machine. The dashboard files are `dashboard/index.html` beside the program. Keep that folder with the executable.

| Argument | Role |
|---|---|
| `--issuing-ca` | Repeat for each `hostname\CA Name`. Two or more expected. |
| `--root-ca-name` | Offline root display name. Not contacted. Default `OFFLINE-ROOT-CA`. |
| `--output` | JSON file. Default `cert-inventory.json`. |
| `--expiry-window-days` | Expiry window. Default 30. |
| `--include-expired` | Also keep certificates that have already expired. |
| `--skip-dns` | Do not resolve CN and DNS SAN names while building the system list. The client-status probe still runs. |
| `--demo` | Write a small file and do not contact a CA, DNS, or the network. |
| `--serve` | After collection, host the on-prem dashboard until Ctrl+C. |
| `--listen` | HTTP prefix. Default `http://127.0.0.1:8787/`. One address, or `http://+:8787/` inside a container. |
| `--self-test` | Check serial rules, shared-certificate rows, and that a bad name is not looked up. |

`--serve` with no issuing CA hosts the JSON already at `--output` and does not contact a CA. To show the console to another host on the same isolated network:

```powershell
.\CertInventory.exe --serve --listen http://10.16.1.50:8787/ --output .\cert-inventory.json
```

If Windows refuses that prefix, reserve it once: `netsh http add urlacl url=http://10.16.1.50:8787/ user=DOMAIN\ops`. Loopback does not need a reservation. The listener answers GET and HEAD only, and only `/` and `/cert-inventory.json`.

Exit codes: `0` collected, `1` nothing collected, `2` collected but at least one issuing CA failed.

The program opens each CA with `CertificateAuthority.View`. If that COM object fails, it falls back to `certutil -view`. The certutil path expects English column labels. COM is the path to use on a non-English CA admin workstation.

`cert-inventory.json` contains host names, serials, and addresses. It is gitignored. Do not commit a live collection.

## How client status is decided

Only a certificate that is still valid is probed: disposition `issued`, `NotBefore` has passed, and `NotAfter` is still in the future. Revoked and expired rows stay in the inventory and do not get a client check.

Each valid certificate is expanded into clients:

1. The common name, with `via` set to `cn`.
2. Each DNS or IP SAN that is not a repeat of that name, with `via` set to `san`.

Email and URI SANs are skipped. The serial on the row is the serial of that certificate. The same client name on two certificates is two rows.

The probe runs once per distinct name. The result is copied onto every certificate that lists that name.

A name is sent to DNS or ping only when it is a DNS name, or a unicast IPv4 address. A name with spaces, a URL, or any other shape is recorded as `not-in-dns` and is not looked up. `0.0.0.0`, `255.255.255.255`, and multicast addresses (`224.0.0.0/4`) are recorded as `not-on-network` and are not pinged.

| Step | Status |
|---|---|
| Not a DNS name | `not-in-dns`, no lookup |
| IPv4 that is not unicast | `not-on-network`, no ping |
| DNS name, no IPv4 answer within 2 seconds | `not-in-dns` |
| Address answers one ICMP echo (1 second) | `active` |
| Ping says the destination is unreachable | `not-on-network` |
| DNS answered, but the ping timed out | `inactive` |

`checkedAt` is the time of that collection. `statusWindowMinutes` is `5`. The console shows "last 5 min" when `checkedAt` is inside that window, and "older than 5 min" when the file is stale. Re-run the collector on the isolated network to refresh it. The console host does not need a route to the public internet.

`--demo` does not touch DNS or ping. A name that contains a dot is marked `active`. A name with no dot is `not-in-dns`.

## Security

- The collector is the only program that talks to the CAs, DNS, and ICMP. The dashboard is hosted by that same process and only reads the JSON file. It makes no outbound call.
- `certutil.exe` is started with `ArgumentList`, not through a shell. The config must be `hostname\CA Name`. It cannot start with `-` or contain quotes, newlines, or shell characters.
- Certificate bytes from the CA are loaded as a certificate with an ephemeral key set. They are not executed.
- JSON is written with the default encoder, so `<` in a name stays escaped.
- Do not commit a live `cert-inventory.json`.

GitHub code scanning (CodeQL, `security-extended`) and a pattern scan run on every push to `main`.

## JSON

Schema `ca-ledger/1`.

```json
{
  "schema": "ca-ledger/1",
  "collectedAt": "2026-10-30T04:00:00.0000000Z",
  "collector": "CertInventory",
  "rootName": "CORP-OFFLINE-ROOT-CA",
  "expiryWindowDays": 30,
  "statusWindowMinutes": 5,
  "issuing": [
    {
      "config": "pki-ica01.corp.local\\CORP-ISSUING-CA-01",
      "host": "pki-ica01.corp.local",
      "name": "CORP-ISSUING-CA-01"
    }
  ],
  "certificates": [],
  "clientChecks": [
    {
      "serial": "4f12a1000001",
      "client": "es-data-01.obs.corp.local",
      "via": "cn",
      "status": "active",
      "checkedAt": "2026-10-30T04:00:00.0000000Z",
      "address": "10.16.8.21"
    }
  ],
  "errors": []
}
```

`via` is `cn` or `san`. Disposition in the CA database is `20` issued or `21` revoked. The file stores `issued` or `revoked`.

Sibling certificate automation: [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation).
