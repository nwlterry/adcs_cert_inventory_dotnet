using System.Text;
using System.Text.Json;

namespace CertInventory;

public static class Program
{
    public static int Main(string[] args)
    {
        if (Has(args, "--self-test")) return Validation.SelfTest();

        var demo = Has(args, "--demo");
        var serve = Has(args, "--serve");
        var includeExpired = Has(args, "--include-expired");
        var skipDns = Has(args, "--skip-dns") || demo;
        var root = Value(args, "--root-ca-name") ?? "OFFLINE-ROOT-CA";
        var output = Value(args, "--output") ?? "cert-inventory.json";
        var listen = Value(args, "--listen") ?? "http://127.0.0.1:8787/";
        var window = 30;
        var windowText = Value(args, "--expiry-window-days");
        if (windowText != null && !int.TryParse(windowText, out window))
        {
            Console.Error.WriteLine("--expiry-window-days must be an integer.");
            return 1;
        }
        var issuing = Values(args, "--issuing-ca");

        if (!demo && issuing.Count == 0)
        {
            if (serve)
                return DashboardHost.Run(Path.GetFullPath(output), listen);

            Console.WriteLine("CertInventory 0.3.0-beta.1");
            Console.WriteLine("Use the CA inventory as the base. Each CN and DNS or IP SAN is a client of that serial.");
            Console.WriteLine("The collector probes the client and records active, inactive, not-in-dns, or not-on-network.");
            Console.WriteLine("Then --serve hosts the on-prem dashboard on this machine. The page does not use the internet.");
            Console.WriteLine();
            Console.WriteLine("  CertInventory --issuing-ca host\\CA-Name --issuing-ca host2\\CA-Name --root-ca-name OFFLINE-ROOT --serve");
            Console.WriteLine("  CertInventory --demo --serve");
            Console.WriteLine("  CertInventory --serve --output cert-inventory.json");
            Console.WriteLine("  CertInventory --self-test");
            Console.WriteLine();
            Console.WriteLine("Default listen address is http://127.0.0.1:8787/. Bind one isolated-network address with --listen.");
            Console.WriteLine("Live collection needs Windows, RSAT AD CS, and a path to every issuing CA.");
            return 1;
        }

        InventorySnapshot snapshot;
        if (demo)
        {
            snapshot = InventoryBuilder.Demo(root, window);
        }
        else
        {
            if (issuing.Count < 2)
                Console.Error.WriteLine("Warning: expected 2 or more issuing CAs for a two-tier PKI. Continuing with " + issuing.Count + ".");
            var issuers = issuing.Select(InventoryBuilder.SplitCa).ToList();
            var certs = new List<CertRecord>();
            var errors = new List<CollectError>();
            foreach (var issuer in issuers)
            {
                Console.WriteLine("Collecting " + issuer.Config);
                try
                {
                    List<CertRecord> rows;
                    try
                    {
                        if (!OperatingSystem.IsWindows())
                            throw new PlatformNotSupportedException("CertificateAuthority.View requires Windows.");
                        rows = CaClient.FromView(issuer, includeExpired, skipDns);
                    }
                    catch (Exception ex)
                    {
                        Console.Error.WriteLine("Warning: COM view failed (" + ex.Message + "). Falling back to certutil.");
                        rows = CaClient.FromCertutil(issuer, includeExpired, skipDns);
                    }
                    certs.AddRange(rows);
                    Console.WriteLine("  " + rows.Count + " rows");
                }
                catch (Exception ex)
                {
                    Console.Error.WriteLine("Warning: " + ex.Message);
                    errors.Add(new CollectError { Config = issuer.Config, Message = ex.Message });
                }
            }
            if (certs.Count == 0)
            {
                Console.WriteLine("No issued certificates were collected.");
                foreach (var err in errors) Console.WriteLine("  " + err.Config + ": " + err.Message);
                return 1;
            }
            snapshot = new InventorySnapshot
            {
                CollectedAt = DateTime.UtcNow.ToString("o"),
                Collector = "CertInventory",
                RootName = root,
                ExpiryWindowDays = window,
                Issuing = issuers,
                Certificates = certs,
                Errors = errors,
            };
        }

        var now = DateTime.UtcNow;
        var demoRun = demo;
        snapshot.ClientChecks = ClientChecks.Build(snapshot.Certificates, now, demoRun);
        snapshot.StatusWindowMinutes = 5;
        snapshot.Comparisons = new();
        snapshot.Validations = new();
        var path = WriteJson(snapshot, output);
        PrintSummary(snapshot, now, window, path);
        var code = snapshot.Errors.Count > 0 ? 2 : 0;
        if (!serve) return code;
        var hosted = DashboardHost.Run(path, listen);
        return hosted != 0 ? hosted : code;
    }

    static void PrintSummary(InventorySnapshot snapshot, DateTime now, int window, string path)
    {
        var valid = snapshot.Certificates.Where(c => Validation.IsValid(c, now)).ToList();
        var expiring = valid.Where(c => DateTimeOffset.Parse(c.NotAfter).UtcDateTime <= now.AddDays(window))
            .OrderBy(c => DateTimeOffset.Parse(c.NotAfter))
            .ToList();
        Console.WriteLine();
        Console.WriteLine("CA Ledger collection");
        Console.WriteLine("  Root     " + snapshot.RootName);
        foreach (var ca in snapshot.Issuing)
        {
            var count = valid.Count(c => c.IssuerName == ca.Name);
            Console.WriteLine("  Issuing  " + ca.Config + "  (" + count + " valid)");
        }
        Console.WriteLine("  Issued records          " + snapshot.Certificates.Count);
        Console.WriteLine("  Valid now               " + valid.Count);
        Console.WriteLine("  Expiring within " + window + " days " + expiring.Count);
        foreach (var row in expiring)
        {
            var ips = row.Resolved.SelectMany(r => r.Ips).Distinct().ToList();
            var ipText = ips.Count == 0 ? "no IP" : string.Join(", ", ips);
            var days = Math.Ceiling((DateTimeOffset.Parse(row.NotAfter).UtcDateTime - now).TotalDays);
            Console.WriteLine($"    {days,3:0}d  {row.Cn}  {ipText}  {row.IssuerName}");
        }
        Console.WriteLine("  Client status, last 5 min");
        var counts = new Dictionary<string, int>
        {
            ["active"] = 0,
            ["inactive"] = 0,
            ["not-in-dns"] = 0,
            ["not-on-network"] = 0,
        };
        foreach (var check in snapshot.ClientChecks)
        {
            if (counts.ContainsKey(check.Status)) counts[check.Status]++;
        }
        Console.WriteLine("    active           " + counts["active"]);
        Console.WriteLine("    inactive         " + counts["inactive"]);
        Console.WriteLine("    not in DNS       " + counts["not-in-dns"]);
        Console.WriteLine("    not on network   " + counts["not-on-network"]);
        foreach (var check in snapshot.ClientChecks.Where(c => c.Status != "active"))
            Console.WriteLine($"    {check.Status,-16} {check.Via,-3} {check.Client}  serial {check.Serial}");
        Console.WriteLine("Wrote " + path);
    }

    static string WriteJson(InventorySnapshot snapshot, string path)
    {
        if (path.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0)
            throw new ArgumentException("Output path is not valid.");
        var full = Path.GetFullPath(path);
        var json = JsonSerializer.Serialize(snapshot, new JsonSerializerOptions
        {
            WriteIndented = true,
        });
        File.WriteAllText(full, json, new UTF8Encoding(false));
        return full;
    }

    static bool Has(string[] args, string name) =>
        args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

    static string? Value(string[] args, string name)
    {
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
        }
        return null;
    }

    static List<string> Values(string[] args, string name)
    {
        var list = new List<string>();
        for (var i = 0; i < args.Length - 1; i++)
        {
            if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase) && !args[i + 1].StartsWith("--"))
                list.Add(args[i + 1]);
        }
        return list;
    }
}
