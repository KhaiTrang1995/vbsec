---
id: CORS-MISCONFIG
severity_max: HIGH
applies_to: dotnet
overrides: generic/15-cors-misconfig.md
---

# CORS Misconfiguration — .NET 10 / ASP.NET Core Specialization

> Override cho rule chung `rules/generic/15-cors-misconfig.md`. Áp dụng khi `primary_language: dotnet`.

## Intent (.NET-specific)

ASP.NET Core (từ 2.x) **chủ động chặn** ở runtime nếu policy gọi `AllowAnyOrigin()` cùng `AllowCredentials()` — combo này throw `InvalidOperationException` khi request tới thay vì âm thầm cho qua. Đây là điểm khác biệt so với Flask-CORS/Django/FastAPI, nơi combo tương tự chạy được (và nguy hiểm). Nhưng vibe code .NET vẫn tạo ra lỗ hổng **tương đương wildcard + credentials** bằng cách dùng `SetIsOriginAllowed(_ => true)` (chấp nhận mọi origin, hợp lệ về mặt code) kết hợp `AllowCredentials()` — bypass hoàn toàn guard của framework vì đây không phải "AllowAny" theo nghĩa literal mà là 1 predicate luôn trả `true`. Ngoài ra, code tự phản chiếu (reflect) header `Origin` thủ công qua middleware custom cũng tạo lỗ hổng y hệt.

## Khi nào HIGH

- `SetIsOriginAllowed(_ => true)` (hoặc predicate luôn trả `true`) kết hợp `AllowCredentials()` trong cùng policy — tương đương wildcard + credentials, framework không chặn được vì không phải `AllowAnyOrigin()` literal.
- Middleware custom tự set `Access-Control-Allow-Origin` bằng cách echo `Request.Headers["Origin"]` mà không validate allowlist, kèm `Access-Control-Allow-Credentials: true`.
- `builder.Services.AddCors(o => o.AddDefaultPolicy(p => p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()))` áp dụng cho endpoint có auth cookie/session — dù không credentials, API vẫn public hoàn toàn cho mọi origin đọc data không cần đăng nhập bảo vệ đúng cách (data leak, không token theft).
- `WithOrigins()` dùng regex/wildcard string không anchor đúng (`"https://*.example.com"` build sai logic so sánh, hoặc so sánh `Contains("example.com")` thủ công) — bypass bằng `evil-example.com` hoặc `example.com.attacker.com`.
- CORS policy áp dụng global (`app.UseCors()` không tên policy cụ thể) trong khi có endpoint nhạy cảm không nên public cross-origin.

## Khi nào MEDIUM (giảm cấp)

- `AllowAnyOrigin()` literal (không có `AllowCredentials()`) — framework tự chặn combo nguy hiểm, chỉ còn risk lộ data public (không token theft). Vẫn nên whitelist nếu API trả PII.
- Whitelist origin cụ thể qua `WithOrigins("https://app.example.com")` — SAFE, không flag.
- Endpoint không có auth cookie/session, chỉ trả public data (healthcheck, public config) — risk thấp.

## Cách reasoning

1. Grep sink: `AddCors`, `SetIsOriginAllowed`, `AllowCredentials`, `AllowAnyOrigin`, `WithOrigins`, middleware tự set `Access-Control-Allow-Origin`.
2. Read toàn bộ policy definition trong `Program.cs`/`Startup.cs` — combo nào áp dụng cùng lúc?
3. Nếu thấy `AllowAnyOrigin().AllowCredentials()` viết literal cùng chỗ — ghi chú đây sẽ crash runtime (không phải finding bảo mật per se, nhưng là bug/DoS khi request tới); vẫn worth flag ở mức thấp hơn kèm giải thích, vì chứng tỏ code chưa hiểu rõ CORS semantics, có thể pattern khác gần đó (`SetIsOriginAllowed`) mới thực sự nguy hiểm.
4. Xác định `SetIsOriginAllowed` predicate — có luôn `true`, hay có logic allowlist thật (so sánh với `HashSet<string>`)?
5. Check endpoint có `[Authorize]`/cookie auth không — quyết định risk là token theft (HIGH) hay chỉ data leak public (MEDIUM).

## Search patterns

```
# SetIsOriginAllowed luôn true + credentials
SetIsOriginAllowed\s*\(\s*_?\s*=>\s*true\s*\)
SetIsOriginAllowed\s*\([^)]*\)[^;]*AllowCredentials\s*\(\s*\)

# Middleware tự reflect Origin
Response\.Headers\s*\[\s*["']Access-Control-Allow-Origin["']\s*\]\s*=\s*.*Request\.Headers\s*\[\s*["']Origin["']
context\.Response\.Headers\.Append\s*\(\s*["']Access-Control-Allow-Origin["']\s*,\s*origin\s*\)

# AllowAnyOrigin + credentials literal (sẽ crash nhưng vẫn đáng note)
AllowAnyOrigin\s*\(\s*\)[^;]*AllowCredentials\s*\(\s*\)

# Global CORS không tên policy cụ thể
app\.UseCors\s*\(\s*\)(?!\s*\(\s*["'])

# Regex/wildcard so sánh sai
WithOrigins\s*\([^)]*\*
\.Contains\s*\(\s*["']example\.com["']\s*\)
```

## Examples

### HIGH — flag

```csharp
// SetIsOriginAllowed luôn true — bypass guard AllowAnyOrigin+AllowCredentials
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
    {
        policy.SetIsOriginAllowed(_ => true)   // chấp nhận MỌI origin
              .AllowAnyMethod()
              .AllowAnyHeader()
              .AllowCredentials();             // + credentials → CRITICAL combo, framework KHÔNG chặn được
    });
});
// Attacker host evil.com → fetch /api/me kèm cookie auth → đọc PII
```

```csharp
// Middleware custom reflect Origin thủ công
app.Use(async (context, next) =>
{
    var origin = context.Request.Headers["Origin"].ToString();
    context.Response.Headers.Append("Access-Control-Allow-Origin", origin);  // echo blindly
    context.Response.Headers.Append("Access-Control-Allow-Credentials", "true");
    await next();
});
```

```csharp
// Regex/so sánh sai — bypass qua subdomain giả
if (origin != null && origin.Contains("example.com"))  // khớp evil-example.com, example.com.attacker.com
{
    context.Response.Headers.Append("Access-Control-Allow-Origin", origin);
}
```

```csharp
// AllowAnyOrigin literal + AllowCredentials — sẽ throw InvalidOperationException runtime
// (bug rõ ràng, nhưng vẫn note vì thể hiện hiểu sai CORS — kiểm tra pattern SetIsOriginAllowed gần đó)
builder.Services.AddCors(options =>
    options.AddPolicy("Bad", p => p.AllowAnyOrigin().AllowCredentials()));
```

### NOT critical — không flag

```csharp
// Whitelist origin cụ thể
builder.Services.AddCors(options =>
{
    options.AddPolicy("Frontend", policy =>
    {
        policy.WithOrigins("https://app.example.com", "https://admin.example.com")
              .AllowAnyMethod()
              .WithHeaders("Authorization", "Content-Type")
              .AllowCredentials();
    });
});
app.UseCors("Frontend");
```

```csharp
// SetIsOriginAllowed với allowlist thật
private static readonly HashSet<string> AllowedOrigins = new()
{
    "https://app.example.com", "https://admin.example.com"
};

policy.SetIsOriginAllowed(origin => AllowedOrigins.Contains(origin))
      .AllowCredentials();
```

```csharp
// AllowAnyOrigin nhưng KHÔNG credentials — public API, chấp nhận
builder.Services.AddCors(options =>
    options.AddPolicy("PublicApi", p => p.AllowAnyOrigin().AllowAnyMethod()));
// Không AllowCredentials() → chỉ lộ data public, không token theft
```

## Fix recommendation

1. **Whitelist tuyệt đối** qua `WithOrigins(...)` với domain cụ thể, không dùng `SetIsOriginAllowed(_ => true)`.
2. **Nếu cần dynamic allowlist**, dùng `SetIsOriginAllowed(origin => AllowedOrigins.Contains(origin))` với `HashSet<string>` so sánh chính xác (không `Contains`/substring match).
3. **Không tự viết middleware reflect Origin** — dùng `AddCors` + `UseCors("PolicyName")` chuẩn của framework, đã có guard sẵn.
4. **Tách policy theo endpoint sensitivity**: public API có thể `AllowAnyOrigin()` (không credentials); API có cookie/session auth luôn whitelist domain cụ thể.
5. **`Vary: Origin`** tự động khi dùng `UseCors` chuẩn — không cần set tay, nhưng nếu tự viết middleware phải nhớ thêm để tránh cache poisoning.
6. **Test bằng `curl -H "Origin: https://evil.com"`** để xác nhận response không echo origin lạ.

## Cross-references

- `11-csrf`: CORS sai + cookie auth = chain với CSRF.
- `14-jwt-none-algorithm`: JWT lưu cookie + CORS misconfig = cross-origin token theft.
- Generic `12-broken-access-control`: CORS chỉ là transport layer, authorization thực sự vẫn phải ở policy/middleware riêng.
