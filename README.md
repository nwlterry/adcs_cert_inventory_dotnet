# AD CS certificate inventory (.NET)

.NET 8 collector for a two-tier AD CS hierarchy (offline root, two or more issuing CAs). For each valid client certificate, look it up by common name, or by exactly one SAN when the common name is not on a valid certificate. The serial number on the certificate that lookup returns is the serial used for validation. When both the common name and that one SAN resolve, the two serials are compared.

The summary also lists certificates that expire within 30 days, with the system name and IP taken from the CN and SAN.

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

## Validation

A certificate is valid when disposition is issued, `NotBefore` has passed, and `NotAfter` is still in the future. Revoked rows stay in the file and are excluded from validation.

For each valid client certificate the program:

1. Looks the certificate up by common name.
2. If that common name is not on a valid issued certificate, looks it up by exactly one SAN: the first DNS name that differs from the CN, otherwise the CN itself, otherwise one IP SAN.
3. Reads the serial number on the certificate that lookup returns. That serial is the validation serial. `verified` is true only when the lookup returns one serial.
4. When both the common name and that one SAN resolve, compares the two serial sets.

| Kind | Meaning |
|---|---|
| `match` | CN and the one SAN resolve to the same single valid serial. |
| `duplicate` | The names agree, but more than one certificate is still valid. Revoke the superseded serial. |
| `divergent` | The SAN is covered by a different set of valid serials than the CN. |
| `mismatch` | The two lookups share no serial. |
| `cn-missing` / `san-missing` | No valid issued certificate for that name. |

`validations[]` is the CN-or-one-SAN lookup and the serial taken from it. `comparisons[]` is the cross-check, and only non-matches are kept.

Output schema is `ca-ledger/1`, the same file the PowerShell collector writes.

Sibling certificate automation: [iis_cert_automation](https://github.com/nwlterry/iis_cert_automation).
