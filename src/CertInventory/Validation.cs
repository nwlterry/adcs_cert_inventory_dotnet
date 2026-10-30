using System.Text.RegularExpressions;

namespace CertInventory;

public static class Validation
{
    public static string NormalizeSerial(string? serial)
    {
        if (string.IsNullOrEmpty(serial)) return "0";
        var hex = Regex.Replace(serial, "[^0-9a-fA-F]", "").ToLowerInvariant().TrimStart('0');
        return hex.Length == 0 ? "0" : hex;
    }

    public static bool IsValid(CertRecord cert, DateTime nowUtc)
    {
        if (!string.Equals(cert.Disposition, "issued", StringComparison.OrdinalIgnoreCase)) return false;
        if (!DateTimeOffset.TryParse(cert.NotBefore, out var start)) return false;
        if (!DateTimeOffset.TryParse(cert.NotAfter, out var end)) return false;
        return start.UtcDateTime <= nowUtc && end.UtcDateTime > nowUtc;
    }

    public static string PickSan(CertRecord cert)
    {
        var dns = cert.Sans.Where(s => s.Type == "dns").ToList();
        foreach (var san in dns)
        {
            if (san.Value.Contains('.') && !san.Value.Equals(cert.Cn, StringComparison.OrdinalIgnoreCase))
                return san.Value;
        }
        foreach (var san in dns)
        {
            if (san.Value.Equals(cert.Cn, StringComparison.OrdinalIgnoreCase)) return san.Value;
        }
        if (dns.Count > 0) return dns[0].Value;
        var ip = cert.Sans.FirstOrDefault(s => s.Type == "ip");
        if (ip != null) return ip.Value;
        return cert.Sans.Count > 0 ? cert.Sans[0].Value : "";
    }

    public static List<Comparison> Findings(IReadOnlyList<CertRecord> certificates, DateTime nowUtc)
    {
        var valid = certificates.Where(c => IsValid(c, nowUtc)).ToList();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var findings = new List<Comparison>();
        foreach (var cert in valid)
        {
            var san = PickSan(cert);
            var key = cert.Cn.ToLowerInvariant() + "|" + san.ToLowerInvariant();
            if (!seen.Add(key)) continue;
            var cnCerts = valid.Where(c => c.Cn.Equals(cert.Cn, StringComparison.OrdinalIgnoreCase)).ToList();
            var sanCerts = valid.Where(c => c.Sans.Any(s => s.Value.Equals(san, StringComparison.OrdinalIgnoreCase))).ToList();
            var cnSerials = UniqueSerials(cnCerts);
            var sanSerials = UniqueSerials(sanCerts);
            var shared = cnSerials.Where(sanSerials.Contains).ToList();
            string kind;
            if (string.IsNullOrWhiteSpace(cert.Cn) || cnCerts.Count == 0) kind = "cn-missing";
            else if (string.IsNullOrWhiteSpace(san) || sanCerts.Count == 0) kind = "san-missing";
            else if (shared.Count == 0) kind = "mismatch";
            else if (SameSet(cnSerials, sanSerials) && cnSerials.Count == 1) kind = "match";
            else if (SameSet(cnSerials, sanSerials)) kind = "duplicate";
            else kind = "divergent";
            if (kind == "match") continue;
            findings.Add(new Comparison
            {
                Cn = cert.Cn,
                San = san,
                Kind = kind,
                CnSerials = cnSerials,
                SanSerials = sanSerials,
            });
        }
        return findings;
    }

    public static List<ClientValidation> ClientValidations(IReadOnlyList<CertRecord> certificates, DateTime nowUtc)
    {
        var valid = certificates.Where(c => IsValid(c, nowUtc)).ToList();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var rows = new List<ClientValidation>();
        foreach (var cert in valid)
        {
            var name = cert.Cn ?? "";
            var via = "cn";
            var key = "cn|" + name.ToLowerInvariant();
            List<CertRecord> matched = new();
            if (!string.IsNullOrWhiteSpace(name))
            {
                matched = valid.Where(c => c.Cn.Equals(name, StringComparison.OrdinalIgnoreCase)).ToList();
            }
            if (matched.Count == 0)
            {
                via = "san";
                name = PickSan(cert);
                key = "san|" + name.ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(name)) continue;
                var lookup = name;
                matched = valid.Where(c => c.Sans.Any(s => s.Value.Equals(lookup, StringComparison.OrdinalIgnoreCase))).ToList();
            }
            if (!seen.Add(key)) continue;
            var serials = UniqueSerials(matched);
            rows.Add(new ClientValidation
            {
                Name = name,
                Via = via,
                Serials = serials,
                Verified = serials.Count == 1,
            });
        }
        return rows;
    }

    public static int SelfTest()
    {
        var failures = new List<string>();
        if (NormalizeSerial("4F 12 A1") != "4f12a1") failures.Add("normalize spaced serial");
        if (NormalizeSerial("0000") != "0") failures.Add("normalize zeros");

        var now = DateTime.UtcNow;
        var demo = InventoryBuilder.Demo("OFFLINE-ROOT-CA", 30);
        var www = ClientChecks.Build(demo.Certificates, now, true).Where(c => c.Client == "www.corp.local").ToList();
        if (www.Count != 2 || www.Select(c => c.Serial).Distinct().Count() != 2)
            failures.Add("shared certificate should list each client, not a conflict");
        if (ClientChecks.Classify(false, false, null) != "not-in-dns") failures.Add("dns miss");
        if (ClientChecks.Classify(true, false, null) != "not-on-network") failures.Add("ip miss");
        if (ClientChecks.Classify(false, true, System.Net.NetworkInformation.IPStatus.Success) != "active") failures.Add("active");
        if (ClientChecks.Classify(false, true, System.Net.NetworkInformation.IPStatus.TimedOut) != "inactive") failures.Add("inactive");
        if (ClientChecks.Classify(false, true, System.Net.NetworkInformation.IPStatus.DestinationHostUnreachable) != "not-on-network")
            failures.Add("unreachable");
        if (ClientChecks.Kind("es-data-01.obs.corp.local") != ProbeKind.Host) failures.Add("host kind");
        if (ClientChecks.Kind("10.16.8.21") != ProbeKind.UnicastIp) failures.Add("unicast kind");
        if (ClientChecks.Kind("bad host") != ProbeKind.RejectedHost) failures.Add("rejected host");
        if (ClientChecks.Kind("224.0.0.1") != ProbeKind.RejectedIp) failures.Add("multicast");
        if (ClientChecks.Kind("0.0.0.0") != ProbeKind.RejectedIp) failures.Add("unspecified");
        var blocked = ClientChecks.Probe("bad host");
        if (blocked.Status != "not-in-dns" || blocked.Address != null) failures.Add("rejected host is not looked up");
        var blockedIp = ClientChecks.Probe("255.255.255.255");
        if (blockedIp.Status != "not-on-network" || blockedIp.Address != null) failures.Add("broadcast is not pinged");

        var sanOnly = new CertRecord
        {
            Cn = "",
            Disposition = "issued",
            NotBefore = now.AddDays(-10).ToString("o"),
            NotAfter = now.AddDays(10).ToString("o"),
            Serial = "ab",
            Sans = new List<SanName> { new() { Type = "dns", Value = "solo.corp.local" } },
        };
        var sanRows = ClientChecks.Build(new[] { sanOnly }, now, true);
        if (sanRows.Count != 1 || sanRows[0].Via != "san" || sanRows[0].Client != "solo.corp.local" || sanRows[0].Serial != "ab")
            failures.Add("SAN client keeps the certificate serial");

        if (failures.Count == 0)
        {
            Console.WriteLine("self-test ok");
            return 0;
        }
        foreach (var failure in failures) Console.Error.WriteLine("self-test failed: " + failure);
        return 1;
    }

    static List<string> UniqueSerials(IEnumerable<CertRecord> certs)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<string>();
        foreach (var cert in certs)
        {
            if (seen.Add(cert.Serial)) list.Add(cert.Serial);
        }
        return list;
    }

    static bool SameSet(List<string> a, List<string> b)
    {
        if (a.Count != b.Count) return false;
        var set = new HashSet<string>(b, StringComparer.Ordinal);
        return a.All(set.Contains);
    }
}
