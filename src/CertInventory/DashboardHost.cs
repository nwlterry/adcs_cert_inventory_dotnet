using System.Net;
using System.Text.RegularExpressions;

namespace CertInventory;

public static class DashboardHost
{
    static readonly Regex PrefixPattern = new(@"\Ahttp://(\+|\*|[A-Za-z0-9._-]+):\d+/\z", RegexOptions.CultureInvariant);

    public static int Run(string jsonPath, string listen)
    {
        var prefix = listen.EndsWith('/') ? listen : listen + "/";
        if (prefix.IndexOfAny(new[] { '\r', '\n', '\0' }) >= 0 || !PrefixPattern.IsMatch(prefix))
        {
            Console.Error.WriteLine("Listen must be one http address with a port, such as http://127.0.0.1:8787/. A container uses http://+:8787/.");
            return 1;
        }
        if (!File.Exists(jsonPath))
        {
            Console.Error.WriteLine("No inventory at " + jsonPath + ". Collect first, or pass --demo --serve.");
            return 1;
        }

        byte[] html;
        try
        {
            html = LoadHtml();
        }
        catch (FileNotFoundException ex)
        {
            Console.Error.WriteLine(ex.Message);
            return 1;
        }

        using var listener = new HttpListener();
        listener.Prefixes.Add(prefix);
        try
        {
            listener.Start();
        }
        catch (HttpListenerException ex)
        {
            Console.Error.WriteLine("Could not listen on " + prefix + ". Loopback usually needs no reservation. For another address on the isolated network, reserve it once: netsh http add urlacl url=" + prefix + " user=DOMAIN\\user. " + ex.Message);
            return 1;
        }

        Console.WriteLine();
        Console.WriteLine("On-prem dashboard  " + prefix);
        Console.WriteLine("This process serves only the console and cert-inventory.json. It does not open an outbound connection.");
        Console.WriteLine("Press Ctrl+C to stop.");

        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            try { listener.Stop(); } catch (ObjectDisposedException) { }
        };

        try
        {
            while (listener.IsListening)
            {
                HttpListenerContext context;
                try
                {
                    context = listener.GetContext();
                }
                catch (HttpListenerException)
                {
                    break;
                }
                catch (ObjectDisposedException)
                {
                    break;
                }

                var request = context.Request;
                var response = context.Response;
                try
                {
                    response.Headers["X-Content-Type-Options"] = "nosniff";
                    response.Headers["Cache-Control"] = "no-store";
                    response.Headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'none'";
                    var method = request.HttpMethod ?? "";
                    if (!method.Equals("GET", StringComparison.OrdinalIgnoreCase) && !method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                    {
                        response.StatusCode = 405;
                    }
                    else
                    {
                        var route = request.Url?.AbsolutePath ?? "/";
                        byte[]? bytes = null;
                        if (route == "/" || route == "/index.html")
                        {
                            response.ContentType = "text/html; charset=utf-8";
                            bytes = html;
                        }
                        else if (route == "/cert-inventory.json")
                        {
                            response.ContentType = "application/json; charset=utf-8";
                            bytes = File.ReadAllBytes(jsonPath);
                        }
                        else
                        {
                            response.StatusCode = 404;
                        }
                        if (bytes != null)
                        {
                            response.ContentLength64 = bytes.Length;
                            if (!method.Equals("HEAD", StringComparison.OrdinalIgnoreCase))
                                response.OutputStream.Write(bytes, 0, bytes.Length);
                        }
                    }
                }
                catch (Exception)
                {
                    try { response.StatusCode = 500; } catch (Exception) { }
                }
                finally
                {
                    try { response.Close(); } catch (Exception) { }
                }
            }
        }
        finally
        {
            try { listener.Close(); } catch (ObjectDisposedException) { }
        }
        return 0;
    }

    static byte[] LoadHtml()
    {
        var beside = Path.Combine(AppContext.BaseDirectory, "dashboard", "index.html");
        if (File.Exists(beside)) return File.ReadAllBytes(beside);
        using var stream = typeof(DashboardHost).Assembly.GetManifestResourceStream("dashboard.index.html");
        if (stream == null)
            throw new FileNotFoundException("On-prem dashboard is missing. Keep dashboard/index.html next to CertInventory.");
        using var buffer = new MemoryStream();
        stream.CopyTo(buffer);
        return buffer.ToArray();
    }
}
