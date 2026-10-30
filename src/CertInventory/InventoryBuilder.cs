using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

namespace CertInventory;

public static class InventoryBuilder
{
    static readonly Dictionary<string, List<string>> DnsCache = new(StringComparer.OrdinalIgnoreCase);

    public static bool IsSystemName(string? name)
    {
        if (string.IsNullOrWhiteSpace(name)) return false;
        if (name.Any(char.IsWhiteSpace) || name.Contains('@')) return false;
        if (System.Text.RegularExpressions.Regex.IsMatch(name, @"^\d{1,3}(\.\d{1,3}){3}$")) return false;
        return name.Contains('.');
    }

    public static IssuingCa SplitCa(string config)
    {
        var clean = config.Trim().TrimStart('\\');
        var parts = clean.Split('\\', 2);
        if (parts.Length < 2 || !SafeToken(parts[0], false) || !SafeToken(parts[1], true))
            throw new ArgumentException("Issuing CA config must be 'hostname\\CA Name'. Got '" + config + "'.");
        return new IssuingCa { Host = parts[0], Name = parts[1], Config = parts[0] + "\\" + parts[1] };
    }

    static bool SafeToken(string value, bool allowSpace)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > 200 || value.StartsWith('-')) return false;
        if (!allowSpace && value.Any(char.IsWhiteSpace)) return false;
        foreach (var c in value)
        {
            if (char.IsControl(c)) return false;
            if (c is '"' or '\'' or '&' or '|' or ';' or '`' or '$' or '<' or '>') return false;
        }
        return true;
    }

    public static CertRecord NewRecord(
        IssuingCa issuer,
        int requestId,
        string serial,
        string commonName,
        string subject,
        string template,
        string requester,
        string notBefore,
        string notAfter,
        string disposition,
        string? revokedWhen,
        IReadOnlyList<SanName> sans,
        bool skipDns)
    {
        var resolved = new List<ResolvedName>();
        var ipSans = sans.Where(s => s.Type == "ip").Select(s => s.Value).ToList();
        var names = new List<(string Name, string From)>();
        if (IsSystemName(commonName)) names.Add((commonName, "cn"));
        foreach (var san in sans)
        {
            if (san.Type == "dns" && IsSystemName(san.Value) && !san.Value.Equals(commonName, StringComparison.OrdinalIgnoreCase))
                names.Add((san.Value, "san"));
        }
        foreach (var entry in names)
        {
            var ips = skipDns ? new List<string>() : ResolveIps(entry.Name);
            if (ips.Count == 0) ips = ipSans;
            resolved.Add(new ResolvedName { Name = entry.Name, Ips = ips.ToList(), From = entry.From });
        }
        return new CertRecord
        {
            Id = issuer.Name + "-" + requestId + "-" + serial,
            RequestId = requestId,
            Serial = serial,
            IssuerConfig = issuer.Config,
            IssuerName = issuer.Name,
            IssuerHost = issuer.Host,
            Cn = commonName,
            Subject = string.IsNullOrWhiteSpace(subject) ? "CN=" + commonName : subject,
            Sans = sans.ToList(),
            Template = string.IsNullOrWhiteSpace(template) ? "Unknown" : template,
            Requester = requester,
            NotBefore = notBefore,
            NotAfter = notAfter,
            Disposition = disposition,
            RevokedWhen = string.IsNullOrWhiteSpace(revokedWhen) ? null : revokedWhen,
            Resolved = resolved,
        };
    }

    public static List<string> ResolveIps(string name)
    {
        if (DnsCache.TryGetValue(name, out var cached)) return cached.ToList();
        var ips = new List<string>();
        try
        {
            var task = Dns.GetHostAddressesAsync(name);
            if (task.Wait(TimeSpan.FromSeconds(2)) && task.Status == TaskStatus.RanToCompletion)
            {
                ips = task.Result
                    .Where(a => a.AddressFamily == AddressFamily.InterNetwork)
                    .Select(a => a.ToString())
                    .Where(ClientChecks.IsUnicastIpv4)
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
            }
        }
        catch
        {
            ips = new List<string>();
        }
        DnsCache[name] = ips;
        return ips.ToList();
    }

    public static string? DispositionOf(object? value)
    {
        var number = 0;
        if (value is int or long or short or byte) number = Convert.ToInt32(value);
        else
        {
            var text = value?.ToString() ?? "";
            var match = System.Text.RegularExpressions.Regex.Match(text, @"(\d+)");
            if (match.Success) number = int.Parse(match.Groups[1].Value);
        }
        if (number is 20 or 3) return "issued";
        if (number is 21 or 6) return "revoked";
        return null;
    }

    public static CertRecord? FromBag(IssuingCa issuer, IDictionary<string, object?> bag, bool includeExpired, bool skipDns)
    {
        var disposition = DispositionOf(Get(bag, "Request.Disposition")) ?? DispositionOf(Get(bag, "Disposition"));
        if (disposition is not ("issued" or "revoked")) return null;

        var requestId = 0;
        if (Get(bag, "RequestID") != null) requestId = Convert.ToInt32(Get(bag, "RequestID"));
        var requester = Get(bag, "Request.RequesterName")?.ToString() ?? "";
        var requestCn = Get(bag, "Request.CommonName")?.ToString() ?? "";
        var template = Get(bag, "CertificateTemplate")?.ToString() ?? "";
        var notBefore = ToIso(Get(bag, "NotBefore"));
        var notAfter = ToIso(Get(bag, "NotAfter"));
        var revokedWhen = ToIso(Get(bag, "RevokedWhen"));
        var serial = Validation.NormalizeSerial(Get(bag, "SerialNumber")?.ToString());
        var subject = "";
        var sans = new List<SanName>();
        var cn = requestCn;

        var raw = AsBytes(Get(bag, "RawCertificate"));
        if (raw != null)
        {
            X509Certificate2? cert = null;
            try
            {
                cert = new X509Certificate2(raw, (string?)null, X509KeyStorageFlags.EphemeralKeySet);
                cn = cert.GetNameInfo(X509NameType.SimpleName, false);
                if (string.IsNullOrWhiteSpace(cn)) cn = requestCn;
                subject = cert.Subject;
                serial = CertificateReader.SerialFromCertificate(cert);
                sans = CertificateReader.ReadSans(cert);
                var fromCert = CertificateReader.ReadTemplate(cert);
                if (!string.IsNullOrWhiteSpace(fromCert)) template = fromCert;
                notBefore = cert.NotBefore.ToUniversalTime().ToString("o");
                notAfter = cert.NotAfter.ToUniversalTime().ToString("o");
            }
            catch
            {
                Console.Error.WriteLine("Warning: request " + requestId + " on " + issuer.Config + " could not be parsed as a certificate.");
            }
            finally
            {
                cert?.Dispose();
            }
        }
        if (string.IsNullOrWhiteSpace(cn) || string.IsNullOrWhiteSpace(notBefore) || string.IsNullOrWhiteSpace(notAfter)) return null;
        if (!includeExpired && DateTimeOffset.Parse(notAfter).UtcDateTime <= DateTime.UtcNow) return null;
        return NewRecord(issuer, requestId, serial, cn, subject, template, requester, notBefore, notAfter, disposition, revokedWhen, sans, skipDns);
    }

    public static InventorySnapshot Demo(string rootName, int expiryWindowDays)
    {
        var now = DateTime.UtcNow;
        string D(int days) => now.AddDays(days).ToString("o");
        var ca1 = new IssuingCa { Config = @"pki-ica01.corp.local\CORP-ISSUING-CA-01", Host = "pki-ica01.corp.local", Name = "CORP-ISSUING-CA-01" };
        var ca2 = new IssuingCa { Config = @"pki-ica02.corp.local\CORP-ISSUING-CA-02", Host = "pki-ica02.corp.local", Name = "CORP-ISSUING-CA-02" };
        var certs = new List<CertRecord>
        {
            NewRecord(ca1, 14021, "4f12a1000001", "es-data-01.obs.corp.local", "CN=es-data-01.obs.corp.local", "Machine", @"CORP\ES-DATA-01$", D(-400), D(200), "issued", null, new[]
            {
                new SanName { Type = "dns", Value = "es-data-01.obs.corp.local" },
                new SanName { Type = "ip", Value = "10.16.8.21" },
            }, true),
            NewRecord(ca1, 10110, "11aa01000001", "web-iis-01.corp.local", "CN=web-iis-01.corp.local", "WebServer", @"CORP\WEB-IIS-01$", D(-320), D(32), "issued", null, new[]
            {
                new SanName { Type = "dns", Value = "web-iis-01.corp.local" },
                new SanName { Type = "dns", Value = "www.corp.local" },
                new SanName { Type = "ip", Value = "10.16.2.31" },
            }, true),
            NewRecord(ca1, 16040, "11aa01000002", "web-iis-01.corp.local", "CN=web-iis-01.corp.local", "WebServer", @"CORP\WEB-IIS-01$", D(-70), D(290), "issued", null, new[]
            {
                new SanName { Type = "dns", Value = "web-iis-01.corp.local" },
                new SanName { Type = "dns", Value = "www.corp.local" },
                new SanName { Type = "ip", Value = "10.16.2.31" },
            }, true),
            NewRecord(ca2, 9602, "d10100000001", "ocp-api.ocp.corp.local", "CN=ocp-api.ocp.corp.local", "WebServer", @"CORP\OCP-API$", D(-200), D(3), "issued", null, new[]
            {
                new SanName { Type = "dns", Value = "ocp-api.ocp.corp.local" },
                new SanName { Type = "ip", Value = "10.16.12.10" },
            }, true),
        };
        return new InventorySnapshot
        {
            CollectedAt = now.ToString("o"),
            Collector = "CertInventory --demo",
            RootName = rootName,
            ExpiryWindowDays = expiryWindowDays,
            Issuing = new List<IssuingCa> { ca1, ca2 },
            Certificates = certs,
        };
    }

    static object? Get(IDictionary<string, object?> bag, string key) => bag.TryGetValue(key, out var value) ? value : null;

    static string? ToIso(object? value)
    {
        if (value == null || value is "") return null;
        if (value is DateTime dt) return dt.ToUniversalTime().ToString("o");
        if (value is double or float or decimal or int) 
        {
            try { return DateTime.FromOADate(Convert.ToDouble(value)).ToUniversalTime().ToString("o"); }
            catch { return null; }
        }
        if (DateTimeOffset.TryParse(value.ToString(), out var parsed)) return parsed.UtcDateTime.ToString("o");
        return null;
    }

    public static byte[]? AsBytes(object? value)
    {
        if (value == null) return null;
        if (value is byte[] bytes) return bytes;
        if (value is string text)
        {
            text = text.Trim();
            if (text.Contains("BEGIN CERTIFICATE"))
                text = RegexStrip(text);
            text = text.Replace(" ", "").Replace("\r", "").Replace("\n", "").Replace("\t", "");
            try { return Convert.FromBase64String(text); }
            catch { return null; }
        }
        return null;
    }

    static string RegexStrip(string text) =>
        System.Text.RegularExpressions.Regex.Replace(text, "-----BEGIN CERTIFICATE-----|-----END CERTIFICATE-----|\\s", "");
}
