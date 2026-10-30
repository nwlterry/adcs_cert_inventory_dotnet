using System.Net.NetworkInformation;
using System.Text.RegularExpressions;

namespace CertInventory;

public static class ClientChecks
{
    static readonly Dictionary<string, (string Status, string? Address)> Cache = new(StringComparer.OrdinalIgnoreCase);

    public static List<(string Client, string Via)> Names(CertRecord cert)
    {
        var rows = new List<(string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrWhiteSpace(cert.Cn))
        {
            rows.Add((cert.Cn.Trim(), "cn"));
            seen.Add(cert.Cn.Trim());
        }
        foreach (var san in cert.Sans)
        {
            if (san.Type is not ("dns" or "ip")) continue;
            var value = san.Value.Trim();
            if (value.Length == 0 || !seen.Add(value)) continue;
            rows.Add((value, "san"));
        }
        return rows;
    }

    public static string Classify(bool isIp, bool resolved, IPStatus? ping)
    {
        if (!resolved) return isIp ? "not-on-network" : "not-in-dns";
        if (ping == IPStatus.Success) return "active";
        if (ping is IPStatus.DestinationUnreachable
            or IPStatus.DestinationHostUnreachable
            or IPStatus.DestinationNetworkUnreachable
            or IPStatus.DestinationProhibited
            or IPStatus.DestinationProtocolUnreachable
            or IPStatus.DestinationPortUnreachable
            or IPStatus.HardwareError
            or IPStatus.BadDestination
            || isIp)
            return "not-on-network";
        return "inactive";
    }

    public static (string Status, string? Address) Probe(string name)
    {
        if (Cache.TryGetValue(name, out var cached)) return cached;
        var isIp = Regex.IsMatch(name, @"^\d{1,3}(\.\d{1,3}){3}$");
        var ips = isIp ? new List<string> { name } : InventoryBuilder.ResolveIps(name);
        string status;
        string? address = null;
        if (ips.Count == 0)
        {
            status = Classify(isIp, false, null);
        }
        else
        {
            address = ips[0];
            IPStatus? ping = null;
            try
            {
                using var sender = new Ping();
                ping = sender.Send(address, 1000).Status;
            }
            catch
            {
                ping = IPStatus.Unknown;
            }
            status = Classify(isIp, true, ping);
        }
        var result = (status, address);
        Cache[name] = result;
        return result;
    }

    public static List<ClientCheck> Build(IReadOnlyList<CertRecord> certificates, DateTime nowUtc, bool demo)
    {
        var checkedAt = nowUtc.ToString("o");
        var rows = new List<ClientCheck>();
        foreach (var cert in certificates.Where(c => Validation.IsValid(c, nowUtc)))
        {
            var fallback = cert.Sans.FirstOrDefault(s => s.Type == "ip")?.Value;
            foreach (var (client, via) in Names(cert))
            {
                string status;
                string? address;
                if (demo)
                {
                    status = client.Contains('.') ? "active" : "not-in-dns";
                    address = status == "not-in-dns" ? null : fallback;
                }
                else
                {
                    var probe = Probe(client);
                    status = probe.Status;
                    address = probe.Address;
                }
                rows.Add(new ClientCheck
                {
                    CertId = cert.Id,
                    Serial = cert.Serial,
                    Client = client,
                    Via = via,
                    Status = status,
                    CheckedAt = checkedAt,
                    Address = address,
                });
            }
        }
        return rows;
    }
}
