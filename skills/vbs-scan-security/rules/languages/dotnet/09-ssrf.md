---
id: SSRF
severity_max: HIGH
applies_to: dotnet
overrides: generic/09-ssrf.md
---

# SSRF (Server-Side Request Forgery) — .NET 10 / ASP.NET Core Specialization

> Override cho rule chung `rules/generic/09-ssrf.md`. Áp dụng khi `primary_language: dotnet`.

## Intent (.NET-specific)

Vibe code .NET hay viết tính năng "fetch URL webhook", "import ảnh từ URL", "generate PDF từ URL", "proxy request" dùng `HttpClient`/`IHttpClientFactory`, `WebRequest`/`HttpWebRequest` (legacy), hoặc `WebClient` (obsolete nhưng vẫn thấy trong code cũ). Không validate host → attacker fetch `http://169.254.169.254/metadata/instance?api-version=2021-02-01` (Azure IMDS) hoặc `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS, nếu host trên AWS) để lấy managed identity token/credentials, hoặc fetch `http://localhost:6379`/internal service khác trong VNet.

Đi cùng họ: **Open Redirect** qua `RedirectResult`/`LocalRedirect` sai cách — `Redirect(returnUrl)` không validate host cho phép phishing trên domain tin cậy của bạn (khác `LocalRedirect` vốn đã validate local path).

## Khi nào HIGH

- `HttpClient.GetAsync(userUrl)`/`PostAsync`/`SendAsync` với `userUrl` là L1 (route/query/body/form), không validate host.
- `IHttpClientFactory`-created client fetch URL từ request mà không qua allowlist.
- `WebRequest.Create(userUrl)`/`HttpWebRequest` legacy với L1 URL.
- `WebClient.DownloadString(userUrl)`/`DownloadData` (API cũ, vẫn nguy hiểm tương đương).
- `Redirect(returnUrl)` (MVC) hoặc `Results.Redirect(url)` (Minimal API) với `url`/`returnUrl` từ query/body không validate host — Open Redirect.
- Webhook URL fetch từ DB nhưng nguồn gốc là L1 (user đăng ký webhook lúc subscribe).
- App host trên Azure/AWS/GCP (có metadata endpoint nội bộ) — tăng impact nếu SSRF thành công.

## Khi nào MEDIUM (giảm cấp)

- URL từ config/appsettings (L3) — chấp nhận nếu chỉ admin set qua config, không qua request.
- Có validate host bằng allowlist domain trước khi gọi `HttpClient`.
- Có chặn IP private/loopback (`IPAddress.IsPrivate`-style check hoặc `System.Net.IPAddress` parse + range check) trước khi fetch.
- Dùng `LocalRedirect()` (đã validate local-only path) thay vì `Redirect()` thô cho returnUrl.

## Cách reasoning

1. Grep sink: `HttpClient\.(Get|Post|Put|Delete|Send)Async`, `WebRequest\.Create`, `WebClient`, `Redirect\s*\(`, `Results\.Redirect`.
2. Read action/handler chứa call, trace URL từ: `[FromQuery]`, `[FromBody]`, `[FromForm]`, route parameter, `HttpContext.Request.Query/Form`.
3. Đặc biệt chú ý URL đi vòng qua DB (webhook URL đăng ký lúc trước, RSS feed URL lưu DB) — vẫn L1 gốc.
4. Verify mitigation:
   - Parse host bằng `Uri` và check allowlist domain?
   - Có resolve DNS rồi check `IPAddress` không phải private/loopback/link-local (`169.254.0.0/16`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`)?
   - `HttpClientHandler.AllowAutoRedirect = false` để chặn redirect bypass?
   - Open redirect dùng `Url.IsLocalUrl(returnUrl)` (MVC helper) trước khi redirect?

## Search patterns

```
# HttpClient direct fetch từ input
HttpClient\s*\(\s*\)\.(Get|Post|Put|Delete|Send)Async\s*\(\s*(request\.|Request\.|\w+Url)
_httpClient\.(Get|Post|Put|Delete|Send)Async\s*\(\s*(request\.|\w+Url)

# WebRequest / WebClient legacy
WebRequest\.Create\s*\(\s*(request\.|\w+Url)
new\s+WebClient\s*\(\s*\)\.(DownloadString|DownloadData)\s*\(

# Open Redirect
\bRedirect\s*\(\s*(returnUrl|request\.Query|Request\.Query)
Results\.Redirect\s*\(\s*(url|returnUrl)\s*\)(?!.*IsLocalUrl)

# Metadata endpoint literal (red flag trong code/test)
169\.254\.169\.254
metadata\.google\.internal
```

## Examples

### HIGH — flag

```csharp
// Minimal API fetch URL từ query, không validate host
app.MapGet("/fetch", async (string url, HttpClient client) =>
{
    var content = await client.GetStringAsync(url);  // L1 url
    return Results.Text(content);
});
// ?url=http://169.254.169.254/metadata/instance?api-version=2021-02-01
// → header Metadata: true bị thiếu trên Azure nhưng nhiều biến thể vẫn khai thác được nội bộ khác
```

```csharp
// Webhook subscription lưu DB rồi fetch lại (L2, gốc L1)
public async Task TriggerWebhook(int webhookId)
{
    var hook = await _db.Webhooks.FindAsync(webhookId);
    await _httpClient.PostAsync(hook.Url, JsonContent.Create(new { evt = "x" }));
    // User đăng ký hook.Url = http://localhost:9200/_cluster/health (Elasticsearch nội bộ)
}
```

```csharp
// Legacy WebRequest với input
[HttpPost("proxy")]
public async Task<IActionResult> Proxy([FromBody] ProxyRequest req)
{
    var request = WebRequest.Create(req.TargetUrl);  // L1
    using var response = await request.GetResponseAsync();
    ...
}
```

```csharp
// Open Redirect — returnUrl không validate host
[HttpGet("login-callback")]
public IActionResult Callback(string returnUrl)
{
    return Redirect(returnUrl);  // ?returnUrl=https://evil.com → phishing trên domain tin cậy
}
```

### NOT critical — không flag

```csharp
// Allowlist host trước khi fetch
private static readonly HashSet<string> AllowedHosts = new() { "api.partner.com", "cdn.example.com" };

app.MapGet("/fetch", async (string url, HttpClient client) =>
{
    var uri = new Uri(url);
    if (!AllowedHosts.Contains(uri.Host))
        return Results.BadRequest();
    return Results.Text(await client.GetStringAsync(uri));
});
```

```csharp
// Chặn IP private/loopback trước khi fetch
static bool IsPrivateOrLoopback(IPAddress ip) =>
    IPAddress.IsLoopback(ip) ||
    (ip.GetAddressBytes() is [10, ..] or [172, >= 16 and <= 31, ..] or [192, 168, ..] or [169, 254, ..]);

var hostEntry = await Dns.GetHostAddressesAsync(new Uri(url).Host);
if (hostEntry.Any(IsPrivateOrLoopback)) return Results.BadRequest();
```

```csharp
// Open redirect an toàn — MVC Url.IsLocalUrl
[HttpGet("login-callback")]
public IActionResult Callback(string returnUrl)
{
    if (Url.IsLocalUrl(returnUrl))
        return Redirect(returnUrl);
    return LocalRedirect("/");
}
```

```csharp
// AllowAutoRedirect=false chống bypass qua redirect chain
var handler = new HttpClientHandler { AllowAutoRedirect = false };
using var client = new HttpClient(handler);
```

## Fix recommendation

1. **Validate URL nhiều tầng**: parse `Uri`, check `Scheme` chỉ `http`/`https`, resolve DNS rồi check IP không private/loopback/link-local/metadata.
2. **Allowlist domain** khi domain space hẹp (webhook partner, CDN cụ thể).
3. **`AllowAutoRedirect = false`** trên `HttpClientHandler`, hoặc re-validate URL sau mỗi redirect nếu buộc phải follow.
4. **Open Redirect**: dùng `Url.IsLocalUrl(returnUrl)` (MVC) trước khi `Redirect()`, hoặc luôn `LocalRedirect()` khi chỉ cần redirect nội bộ.
5. **`IHttpClientFactory`** với named/typed client cấu hình sẵn base address cố định thay vì nhận URL tùy ý từ request khi có thể.
6. **Egress policy ở infra**: network policy/firewall chặn outbound tới `169.254.169.254` và các range private trừ khi thực sự cần (defense in depth).

## Cross-references

- Generic `12-broken-access-control`: endpoint fetch/proxy thường thiếu auth.
- `17-verbose-error-debug-mode`: response lỗi có thể leak nội dung fetch được từ internal service.
- `15-cors-misconfig`: SSRF kết hợp CORS misconfig có thể mở đường exfiltrate dữ liệu ra ngoài dễ hơn.
