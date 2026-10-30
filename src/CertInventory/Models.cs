using System.Text.Json.Serialization;

namespace CertInventory;

public sealed class SanName
{
    [JsonPropertyName("type")] public string Type { get; set; } = "dns";
    [JsonPropertyName("value")] public string Value { get; set; } = "";
}

public sealed class ResolvedName
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("ips")] public List<string> Ips { get; set; } = new();
    [JsonPropertyName("from")] public string From { get; set; } = "cn";
}

public sealed class IssuingCa
{
    [JsonPropertyName("config")] public string Config { get; set; } = "";
    [JsonPropertyName("host")] public string Host { get; set; } = "";
    [JsonPropertyName("name")] public string Name { get; set; } = "";
}

public sealed class CertRecord
{
    [JsonPropertyName("id")] public string Id { get; set; } = "";
    [JsonPropertyName("requestId")] public int RequestId { get; set; }
    [JsonPropertyName("serial")] public string Serial { get; set; } = "0";
    [JsonPropertyName("issuerConfig")] public string IssuerConfig { get; set; } = "";
    [JsonPropertyName("issuerName")] public string IssuerName { get; set; } = "";
    [JsonPropertyName("issuerHost")] public string IssuerHost { get; set; } = "";
    [JsonPropertyName("cn")] public string Cn { get; set; } = "";
    [JsonPropertyName("subject")] public string Subject { get; set; } = "";
    [JsonPropertyName("sans")] public List<SanName> Sans { get; set; } = new();
    [JsonPropertyName("template")] public string Template { get; set; } = "Unknown";
    [JsonPropertyName("requester")] public string Requester { get; set; } = "";
    [JsonPropertyName("notBefore")] public string NotBefore { get; set; } = "";
    [JsonPropertyName("notAfter")] public string NotAfter { get; set; } = "";
    [JsonPropertyName("disposition")] public string Disposition { get; set; } = "";
    [JsonPropertyName("revokedWhen")] public string? RevokedWhen { get; set; }
    [JsonPropertyName("resolved")] public List<ResolvedName> Resolved { get; set; } = new();
}

public sealed class Comparison
{
    [JsonPropertyName("cn")] public string Cn { get; set; } = "";
    [JsonPropertyName("san")] public string San { get; set; } = "";
    [JsonPropertyName("kind")] public string Kind { get; set; } = "";
    [JsonPropertyName("cnSerials")] public List<string> CnSerials { get; set; } = new();
    [JsonPropertyName("sanSerials")] public List<string> SanSerials { get; set; } = new();
}

public sealed class ClientValidation
{
    [JsonPropertyName("name")] public string Name { get; set; } = "";
    [JsonPropertyName("via")] public string Via { get; set; } = "cn";
    [JsonPropertyName("serials")] public List<string> Serials { get; set; } = new();
    [JsonPropertyName("verified")] public bool Verified { get; set; }
}

public sealed class ClientCheck
{
    [JsonPropertyName("certId")] public string CertId { get; set; } = "";
    [JsonPropertyName("serial")] public string Serial { get; set; } = "";
    [JsonPropertyName("client")] public string Client { get; set; } = "";
    [JsonPropertyName("via")] public string Via { get; set; } = "cn";
    [JsonPropertyName("status")] public string Status { get; set; } = "not-in-dns";
    [JsonPropertyName("checkedAt")] public string CheckedAt { get; set; } = "";
    [JsonPropertyName("address")] public string? Address { get; set; }
}

public sealed class CollectError
{
    [JsonPropertyName("config")] public string Config { get; set; } = "";
    [JsonPropertyName("message")] public string Message { get; set; } = "";
}

public sealed class InventorySnapshot
{
    [JsonPropertyName("schema")] public string Schema { get; set; } = "ca-ledger/1";
    [JsonPropertyName("collectedAt")] public string CollectedAt { get; set; } = "";
    [JsonPropertyName("collector")] public string Collector { get; set; } = "CertInventory";
    [JsonPropertyName("rootName")] public string RootName { get; set; } = "";
    [JsonPropertyName("expiryWindowDays")] public int ExpiryWindowDays { get; set; } = 30;
    [JsonPropertyName("issuing")] public List<IssuingCa> Issuing { get; set; } = new();
    [JsonPropertyName("certificates")] public List<CertRecord> Certificates { get; set; } = new();
    [JsonPropertyName("errors")] public List<CollectError> Errors { get; set; } = new();
    [JsonPropertyName("clientChecks")] public List<ClientCheck> ClientChecks { get; set; } = new();
    [JsonPropertyName("statusWindowMinutes")] public int StatusWindowMinutes { get; set; } = 5;
    [JsonPropertyName("comparisons")] public List<Comparison> Comparisons { get; set; } = new();
    [JsonPropertyName("validations")] public List<ClientValidation> Validations { get; set; } = new();
}
