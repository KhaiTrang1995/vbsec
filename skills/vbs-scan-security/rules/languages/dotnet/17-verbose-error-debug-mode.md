---
id: VERBOSE-ERROR-DEBUG-MODE
severity_max: HIGH
applies_to: dotnet
overrides: generic/17-verbose-error-debug-mode.md
---

# Verbose Error & Debug Mode — .NET 10 / ASP.NET Core Specialization

> Override cho rule chung `rules/generic/17-verbose-error-debug-mode.md`. Áp dụng khi `primary_language: dotnet`.

## Intent (.NET-specific)

`app.UseDeveloperExceptionPage()` là middleware mặc định trong template ASP.NET Core mới (`dotnet new webapi`) — vibe code copy nguyên `Program.cs` mẫu rồi deploy thẳng lên prod. Trang exception page hiển thị **full stack trace + source code snippet + query string + cookie + request headers + tất cả environment variables** — tương đương Django `DEBUG=True` hoặc Flask Werkzeug debugger. Khác biệt: Developer Exception Page **không có RCE console** như Werkzeug, nhưng leak connection string, JWT secret, API key trong env var vẫn là CRITICAL-tier info disclosure, đủ để pivot sang chiếm toàn bộ hệ thống.

Nguồn gây lỗi phổ biến: `ASPNETCORE_ENVIRONMENT=Development` bị set nhầm trên container/VM production (env var quyết định branch `if (app.Environment.IsDevelopment())` trong `Program.cs` mẫu), hoặc code không có branch theo environment mà gọi `UseDeveloperExceptionPage()` không điều kiện.

## Khi nào HIGH

- `app.UseDeveloperExceptionPage()` được gọi không có guard `if (app.Environment.IsDevelopment())`.
- `ASPNETCORE_ENVIRONMENT=Development` set trong `appsettings.json`/Dockerfile/deployment manifest dùng cho production.
- Không có `app.UseExceptionHandler(...)` fallback cho non-development — nghĩa là khi environment detect sai, exception page vẫn có thể lộ.
- `builder.Services.AddDatabaseDeveloperPageExceptionFilter()` (EF Core) đăng ký không guard — trang lỗi EF hiển thị connection string + migration pending.
- Custom exception handler tự trả `exception.ToString()` hoặc `exception.StackTrace` trong response body (`return Results.Problem(detail: ex.ToString())`).
- Swagger/OpenAPI UI (`app.UseSwaggerUI()`) enable không guard trên production, cùng lộ endpoint internal không nhằm public.
- `IdentityModelEventSource.ShowPII = true` không guard — log token claims đầy đủ (PII leak vào log, không phải response, nhưng vẫn HIGH khi log tập trung không kiểm soát access).

## Khi nào MEDIUM (giảm cấp)

- `IsDevelopment()` guard đúng, nhưng environment variable injection từ CI/CD có rủi ro set nhầm (note review pipeline, không tự flag code).
- Exception detail chỉ log vào file/Application Insights/Serilog sink, không trả về response.
- Swagger UI guard bằng `IsDevelopment()` hoặc bảo vệ bằng auth riêng (Basic Auth/API key) trên môi trường staging.

## Cách reasoning

1. Grep sink: `UseDeveloperExceptionPage`, `AddDatabaseDeveloperPageExceptionFilter`, `ex.ToString()`/`ex.StackTrace` trong response, `UseSwaggerUI`, `ShowPII`.
2. Read `Program.cs`/`Startup.cs` — có branch theo `app.Environment.IsDevelopment()` hay gọi không điều kiện?
3. Kiểm tra deployment config (`appsettings.Production.json`, Dockerfile `ENV ASPNETCORE_ENVIRONMENT`, k8s manifest) — giá trị thực tế deploy là gì?
4. Xác nhận có `UseExceptionHandler("/Error")` hoặc middleware custom cho non-dev không.
5. Chỉ flag khi middleware/config có khả năng chạy trên production thực tế (không branch hoặc branch check nhầm biến).

## Search patterns

```
# Developer exception page không guard
UseDeveloperExceptionPage\s*\(\s*\)
(?<!IsDevelopment\(\)\s*\)\s*\{\s*[^}]*)UseDeveloperExceptionPage

# EF Core dev exception filter
AddDatabaseDeveloperPageExceptionFilter\s*\(\s*\)

# Environment misconfigured
ASPNETCORE_ENVIRONMENT\s*[=:]\s*["']?Development["']?

# Exception detail leak vào response
Results\.Problem\s*\([^)]*\bex(ception)?\.(ToString|StackTrace|Message)
return\s+.*\bex(ception)?\.ToString\s*\(\s*\)
JsonResult\s*\([^)]*StackTrace

# Swagger enabled không guard
UseSwaggerUI\s*\(\s*\)(?!.*IsDevelopment)

# IdentityModel PII log
IdentityModelEventSource\.ShowPII\s*=\s*true
```

## Examples

### HIGH — flag

```csharp
// Program.cs — không có branch theo environment
var app = builder.Build();

app.UseDeveloperExceptionPage();  // luôn bật, kể cả prod
app.MapControllers();
app.Run();
```

```csharp
// Guard sai biến — luôn true vì typo/logic lỗi
if (true || app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
}
```

```csharp
// Custom exception handler leak stack trace
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var ex = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        await context.Response.WriteAsJsonAsync(new { error = ex?.ToString() });  // CRITICAL leak
    });
});
```

```csharp
// EF Core dev filter không guard
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
// Trang lỗi EF hiển thị connection string đầy đủ khi migration pending
```

```dockerfile
# Dockerfile deploy prod nhưng set Development
ENV ASPNETCORE_ENVIRONMENT=Development
```

### NOT critical — không flag

```csharp
// Guard đúng theo environment
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage();
    app.UseSwaggerUI();
}
else
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.MapControllers();
app.Run();
```

```csharp
// Exception handler generic, log riêng qua Serilog
app.UseExceptionHandler(errorApp =>
{
    errorApp.Run(async context =>
    {
        var ex = context.Features.Get<IExceptionHandlerFeature>()?.Error;
        Log.Error(ex, "Unhandled exception");  // vào log, không vào response
        await context.Response.WriteAsJsonAsync(new { error = "Internal server error" });
    });
});
```

## Fix recommendation

1. Luôn branch theo `app.Environment.IsDevelopment()` cho `UseDeveloperExceptionPage()`/`UseSwaggerUI()`; non-dev dùng `UseExceptionHandler("/Error")` + `UseHsts()`.
2. Không bao giờ trả `exception.ToString()`/`StackTrace` trong response body của môi trường production — log qua Serilog/Application Insights.
3. `AddDatabaseDeveloperPageExceptionFilter()` chỉ đăng ký trong branch dev.
4. Kiểm tra deployment pipeline (Dockerfile, k8s manifest, App Service config) đảm bảo `ASPNETCORE_ENVIRONMENT=Production` cho môi trường thực.
5. `IdentityModelEventSource.ShowPII` chỉ set `true` trong local debug, không commit vào code chạy prod.
6. Bảo vệ Swagger UI trên staging bằng auth riêng nếu cần giữ lại để test.

## Cross-references

- `01-hardcoded-secret`: connection string/API key trong `appsettings.json` lộ qua Developer Exception Page.
- `02-sql-injection`: EF Core dev exception filter leak câu SQL kèm parameter.
- `14-jwt-none-algorithm`: JWT signing key hardcode lộ qua error page dẫn tới forge token.
