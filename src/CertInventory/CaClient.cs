using System.Diagnostics;
using System.Reflection;
using System.Runtime.Versioning;
using System.Text.RegularExpressions;

namespace CertInventory;

public static class CaClient
{
    const int SeekGe = 8;
    const int OutBase64 = 1;
    const int OutBinary = 2;

    [SupportedOSPlatform("windows")]
    public static List<CertRecord> FromView(IssuingCa issuer, bool includeExpired, bool skipDns)
    {
        var viewType = Type.GetTypeFromProgID("CertificateAuthority.View");
        if (viewType == null) throw new InvalidOperationException("CertificateAuthority.View is not registered. Install RSAT AD CS (certadm.dll).");
        var view = Activator.CreateInstance(viewType) ?? throw new InvalidOperationException("CertificateAuthority.View could not be created.");
        var opened = false;
        Exception? last = null;
        foreach (var candidate in new[] { issuer.Config, "\\\\" + issuer.Config })
        {
            try
            {
                Invoke(view, "OpenConnection", candidate);
                opened = true;
                break;
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }
        if (!opened) throw new InvalidOperationException("CertificateAuthority.View could not open '" + issuer.Config + "'. " + last?.Message);

        var wanted = new[]
        {
            "RequestID", "SerialNumber", "Request.RequesterName", "Request.CommonName", "Request.Disposition",
            "NotBefore", "NotAfter", "CertificateTemplate", "RevokedWhen", "RawCertificate",
        };
        var indexes = new List<(string Name, int Index)>();
        foreach (var name in wanted)
        {
            try
            {
                var idx = Convert.ToInt32(Invoke(view, "GetColumnIndex", 0, name));
                if (idx >= 0) indexes.Add((name, idx));
            }
            catch
            {
                // Column is not on this CA.
            }
        }
        if (indexes.Count == 0) throw new InvalidOperationException("No readable columns on '" + issuer.Config + "'.");
        Invoke(view, "SetResultColumnCount", indexes.Count);
        foreach (var col in indexes) Invoke(view, "SetResultColumn", col.Index);

        if (!includeExpired)
        {
            try
            {
                var notAfterIndex = Convert.ToInt32(Invoke(view, "GetColumnIndex", 0, "NotAfter"));
                if (notAfterIndex >= 0)
                    Invoke(view, "SetRestriction", notAfterIndex, SeekGe, 0, DateTime.Now);
            }
            catch
            {
                Console.Error.WriteLine("Warning: could not restrict NotAfter on " + issuer.Config + ". Filtering in memory.");
            }
        }

        var rowset = Invoke(view, "OpenView") ?? throw new InvalidOperationException("OpenView returned nothing.");
        var records = new List<CertRecord>();
        for (var guard = 0; guard < 100000; guard++)
        {
            var rowIndex = Convert.ToInt32(Invoke(rowset, "Next") ?? -1);
            if (rowIndex == -1) break;
            var bag = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            var column = Invoke(rowset, "EnumCertViewColumn") ?? throw new InvalidOperationException("EnumCertViewColumn returned nothing.");
            while (true)
            {
                var colIndex = Convert.ToInt32(Invoke(column, "Next") ?? -1);
                if (colIndex == -1) break;
                string colName;
                try { colName = Invoke(column, "GetName")?.ToString() ?? ""; }
                catch { continue; }
                bag[colName] = ReadColumn(column, colName);
            }
            var record = InventoryBuilder.FromBag(issuer, bag, includeExpired, skipDns);
            if (record != null) records.Add(record);
        }
        return records;
    }

    public static List<CertRecord> FromCertutil(IssuingCa issuer, bool includeExpired, bool skipDns)
    {
        var blocks = new List<string>();
        foreach (var code in new[] { "Disposition=20", "Disposition=21" })
        {
            var psi = new ProcessStartInfo
            {
                FileName = "certutil.exe",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            psi.ArgumentList.Add("-config");
            psi.ArgumentList.Add(issuer.Config);
            psi.ArgumentList.Add("-view");
            psi.ArgumentList.Add("-restrict");
            psi.ArgumentList.Add(code);
            psi.ArgumentList.Add("-out");
            psi.ArgumentList.Add("RequestID,SerialNumber,Request.RequesterName,Request.CommonName,CertificateTemplate,NotBefore,NotAfter,Request.Disposition,RevokedWhen,RawCertificate");
            using var process = Process.Start(psi) ?? throw new InvalidOperationException("certutil.exe could not start.");
            var output = process.StandardOutput.ReadToEnd() + process.StandardError.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0 && !output.Contains("Row "))
                throw new InvalidOperationException("certutil failed for " + issuer.Config + ": " + output.Trim());
            foreach (var part in Regex.Split(output, "(?m)^Row \\d+:\\s*$"))
            {
                if (!string.IsNullOrWhiteSpace(part) && part.Contains("Request ID:")) blocks.Add(part);
            }
        }

        var records = new List<CertRecord>();
        foreach (var block in blocks)
        {
            var bag = new Dictionary<string, object?>(StringComparer.OrdinalIgnoreCase);
            var id = Regex.Match(block, @"(?m)Request ID:\s*""?(\d+)");
            if (id.Success) bag["RequestID"] = int.Parse(id.Groups[1].Value);
            var requester = Regex.Match(block, @"(?m)Requester Name:\s*(.+)$");
            if (requester.Success) bag["Request.RequesterName"] = requester.Groups[1].Value.Trim();
            var cn = Regex.Match(block, @"(?m)(?:Request Common Name|Common Name):\s*(.+)$");
            if (cn.Success) bag["Request.CommonName"] = cn.Groups[1].Value.Trim().Trim('"');
            var template = Regex.Match(block, @"(?m)Certificate Template:\s*(.+)$");
            if (template.Success) bag["CertificateTemplate"] = template.Groups[1].Value.Trim();
            var serial = Regex.Match(block, @"(?m)Serial Number:\s*""?([0-9A-Fa-f ]+)");
            if (serial.Success) bag["SerialNumber"] = serial.Groups[1].Value.Trim().Trim('"');
            var disposition = Regex.Match(block, @"(?m)Request Disposition:.*?(\d+)");
            if (disposition.Success) bag["Request.Disposition"] = int.Parse(disposition.Groups[1].Value);
            var pem = Regex.Match(block, @"-----BEGIN CERTIFICATE-----[\sA-Za-z0-9+/=]+-----END CERTIFICATE-----");
            bag["RawCertificate"] = pem.Success ? pem.Value : HexDump(block);
            var record = InventoryBuilder.FromBag(issuer, bag, includeExpired, skipDns);
            if (record != null) records.Add(record);
        }
        return records;
    }

    static object? ReadColumn(object column, string name)
    {
        if (name == "RawCertificate")
        {
            try
            {
                var binary = InventoryBuilder.AsBytes(Invoke(column, "GetValue", OutBinary));
                if (binary != null) return binary;
            }
            catch
            {
                // Fall through to base64.
            }
            try { return InventoryBuilder.AsBytes(Invoke(column, "GetValue", OutBase64)); }
            catch { return null; }
        }
        try { return Invoke(column, "GetValue", 0); }
        catch { return null; }
    }

    static byte[]? HexDump(string block)
    {
        var list = new List<byte>();
        foreach (var line in block.Split('\n'))
        {
            var match = Regex.Match(line, @"^\s+[0-9A-Fa-f]{4}\s{2}((?:[0-9A-Fa-f]{2}\s+)+)");
            if (!match.Success) continue;
            foreach (var hex in match.Groups[1].Value.Split(' ', StringSplitOptions.RemoveEmptyEntries))
                list.Add(Convert.ToByte(hex, 16));
        }
        return list.Count == 0 ? null : list.ToArray();
    }

    static object? Invoke(object target, string name, params object?[] args)
    {
        try
        {
            return target.GetType().InvokeMember(
                name,
                BindingFlags.InvokeMethod | BindingFlags.Public | BindingFlags.Instance,
                null,
                target,
                args);
        }
        catch (TargetInvocationException ex) when (ex.InnerException != null)
        {
            throw ex.InnerException;
        }
    }
}
