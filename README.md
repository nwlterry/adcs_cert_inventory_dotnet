# AD CS certificate inventory (.NET)

.NET 8 collector for a two-tier AD CS hierarchy (offline root, two or more issuing CAs). The CA inventory is the base. For each valid certificate, every common name and SAN is a client of that serial. Several clients may use the same certificate; that is not a conflict.

The collector then probes each client on the local network. The result is the last-5-minute status: active, inactive, not in DNS, or not on the network. Copy the JSON to the console host. The console does not use the internet.

Live collection runs on a workstation that can reach every issuing CA and has the Certification Authority tools installed (`certadm.dll`, RSAT: AD CS). `--demo` and `--self-test` do not contact a CA.

The offline root is recorded by name only. End-entity rows come from the issuing CAs.

PowerShell port: [adcs_cert_inventory](https://github.com/nwlterry/adcs_cert_inventory).

## Collect

```powershell
dotnet run --project src/CertInventory -- --issuing-ca 'pki-ica01.corp.local\CORP-ISSUING-CA-01' --issuing-ca 'pki-ica02.corp.local\CORP-ISSUING-CA-02' --root-ca-name 'CORP-OFFLINE-ROOT-CA' --output .\cert-inventory.json
```

After `dotnet publish`:

```powershell
.\CertInventory.exe --issuing-ca 'pki-ica01.corp.local\CORP-ISSUING-CA-01' --issuing-ca 'pki-ica02.corp.local\CORP-ISSUING-CA-02' --root-ca-name 'CORP-OFFLINE-ROOT-CA'
```

| Argument | Role |
|---|---|
| `--issuing-ca` | Repeat for each `hostname\CA Name`. Two or more expected. |
| `--root-ca-name` | Offline root display name. Not contacted. Default `OFFLINE-ROOT-CA`. |
| `--output` | JSON file. Default `cert-inventory.json`. |
| `--expiry-window-days` | Expiry window. Default 30. |
| `--include-expired` | Also keep certificates that have already expired. |
| `--skip-dns` | Do not resolve CN and DNS SAN names. IP SANs are still recorded. |
| `--demo` | Write a small file and do not contact a CA. |
| `--self-test` | Check serial normalization, the demo duplicate, and a SAN-only lookup. |

Exit codes: `0` collected, `1` nothing collected, `2` collected but at least one issuing CA failed.

The program opens each CA with `CertificateAuthority.View`. If that COM object fails, it falls back to `certutil -view`. The certutil path expects English column labels. COM is the path to use on a non-English CA admin workstation.

`cert-inventory.json` contains host names, serials, and addresses. It is gitignored. Do not commit a live collection.

## Clients

A certificate is valid when disposition is issued, `NotBefore` has passed, and `NotAfter` is still in the future.

For each valid certificate the program:

1. Reads the certificate serial from the CA inventory.
2. Lists the common name, then each DNS or IP SAN, as a client of that serial.
3. Probes the client on this network (DNS, then one ICMP echo, 1 second).

| Status | Meaning |
|---|---|
| `active` | The name resolved, or it is an IP, and the probe answered. |
| `inactive` | DNS has the name, but the host did not answer. |
| `not-in-dns` | No DNS record. |
| `not-on-network` | The address is known, but the network path did not answer (unreachable). |

`clientChecks[]` is that list. `checkedAt` is the probe time. The console treats a check as the last 5 minutes when the file is newer than `statusWindowMinutes` (default 5). Re-run the collector on the isolated network to refresh it. The console does not resolve client names and does not need a route to the public internet.

Output schema is `ca-ledger/1`, the same file the PowerShell collector writes.

Sibling certificate automation: [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation).
