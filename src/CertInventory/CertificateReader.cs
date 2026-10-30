using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;

namespace CertInventory;

public static class CertificateReader
{
    public static string SerialFromCertificate(X509Certificate2 certificate)
    {
        var bytes = certificate.GetSerialNumber();
        if (bytes == null || bytes.Length == 0) return "0";
        Array.Reverse(bytes);
        var hex = Convert.ToHexString(bytes).ToLowerInvariant();
        return Validation.NormalizeSerial(hex);
    }

    public static List<SanName> ReadSans(X509Certificate2 certificate)
    {
        var ext = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "2.5.29.17");
        if (ext == null) return new List<SanName>();
        return ReadGeneralNames(ext.RawData);
    }

    public static string ReadTemplate(X509Certificate2 certificate)
    {
        var v1 = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "1.3.6.1.4.1.311.20.2");
        if (v1 != null)
        {
            var fmt = v1.Format(false);
            if (!string.IsNullOrWhiteSpace(fmt))
            {
                var parts = fmt.Split('=', 2);
                return parts[^1].Trim();
            }
        }
        var v2 = certificate.Extensions.Cast<X509Extension>().FirstOrDefault(e => e.Oid?.Value == "1.3.6.1.4.1.311.21.7");
        if (v2 != null)
        {
            var fmt = v2.Format(false) ?? "";
            var match = Regex.Match(fmt, @"\(([^)]+)\)");
            if (match.Success) return match.Groups[1].Value;
            if (!string.IsNullOrWhiteSpace(fmt)) return fmt;
        }
        return "";
    }

    public static List<SanName> ReadGeneralNames(byte[]? bytes)
    {
        var names = new List<SanName>();
        if (bytes == null || bytes.Length < 2) return names;
        var offset = 0;
        if (bytes[0] == 0x04)
        {
            offset = 1;
            var outer = ReadDerLength(bytes, ref offset);
            if (outer < 0) return names;
        }
        if (offset >= bytes.Length || bytes[offset] != 0x30) return names;
        offset++;
        var seqLen = ReadDerLength(bytes, ref offset);
        if (seqLen < 0) return names;
        var end = Math.Min(bytes.Length, offset + seqLen);
        while (offset < end)
        {
            var tag = (int)bytes[offset];
            offset++;
            var len = ReadDerLength(bytes, ref offset);
            if (len < 0 || offset + len > bytes.Length) break;
            var payload = new byte[len];
            Buffer.BlockCopy(bytes, offset, payload, 0, len);
            offset += len;
            var choice = tag & 0x1F;
            if (choice is 2 or 1 or 6)
            {
                var type = choice switch { 1 => "email", 6 => "uri", _ => "dns" };
                names.Add(new SanName { Type = type, Value = Encoding.ASCII.GetString(payload) });
            }
            else if (choice == 7)
            {
                string? ip = null;
                if (payload.Length == 4) ip = string.Join('.', payload.Select(b => b.ToString()));
                else if (payload.Length == 16)
                {
                    var parts = new string[8];
                    for (var i = 0; i < 16; i += 2) parts[i / 2] = payload[i].ToString("x2") + payload[i + 1].ToString("x2");
                    ip = string.Join(':', parts);
                }
                if (ip != null) names.Add(new SanName { Type = "ip", Value = ip });
            }
        }
        return names;
    }

    public static int ReadDerLength(byte[] bytes, ref int offset)
    {
        if (offset >= bytes.Length) return -1;
        var first = (int)bytes[offset];
        offset++;
        if ((first & 0x80) == 0) return first;
        var count = first & 0x7F;
        if (count == 0 || count > 4) return -1;
        var length = 0;
        for (var i = 0; i < count; i++)
        {
            if (offset >= bytes.Length) return -1;
            length = (length << 8) | bytes[offset];
            offset++;
        }
        return length;
    }
}
