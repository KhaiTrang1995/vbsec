# .NET 10 Specialization Rules

Specialization này áp dụng cho `primary_language: dotnet`, bao phủ C# / ASP.NET Core / Minimal API / EF Core / Razor / Blazor / Newtonsoft.Json / `System.Diagnostics.Process`.

**v0.6.1**: 9/9 override — ngang mức chuyên sâu với TypeScript (v0.2) và Python (v0.4).

## Rules

| Rule | File | Focus |
|---|---|---|
| XSS | `03-xss.md` | Razor `@Html.Raw`, Blazor `MarkupString`, Minimal API trả HTML ghép string |
| SQL-INJECTION | `02-sql-injection.md` | EF Core raw SQL (`FromSqlRaw`, `ExecuteSqlRaw`), ADO.NET `SqlCommand` |
| MASS-ASSIGNMENT | `07-mass-assignment.md` | ASP.NET Core model binding trực tiếp vào entity/domain model |
| INSECURE-DESERIALIZATION | `08-insecure-deserialization.md` | Newtonsoft `TypeNameHandling`, BinaryFormatter/NetDataContractSerializer/LosFormatter legacy |
| SSRF | `09-ssrf.md` | `HttpClient`/`WebRequest`/`WebClient` fetch URL không allowlist, Open Redirect qua `Redirect()` |
| JWT-NONE-ALGORITHM | `14-jwt-none-algorithm.md` | `TokenValidationParameters` thiếu `ValidateIssuerSigningKey`, weak/hardcoded signing key, algorithm confusion HS/RS256 |
| CORS-MISCONFIG | `15-cors-misconfig.md` | `SetIsOriginAllowed(_ => true)` + `AllowCredentials()`, middleware tự reflect Origin |
| VERBOSE-ERROR-DEBUG-MODE | `17-verbose-error-debug-mode.md` | `UseDeveloperExceptionPage()` không guard, EF Core dev exception filter, exception leak vào response |
| COMMAND-INJECTION | `21-command-injection.md` | `Process.Start`, `ProcessStartInfo`, shell invocation, unsafe argument construction |

## Detection notes

`dotnet` nên được detect từ `.cs`, `.csproj`, `.sln`, `global.json`, `appsettings.json`. Khi repo có frontend TypeScript + backend ASP.NET Core, load cả `typescript` và `dotnet` overlay nếu cả hai vượt ngưỡng.

## Reasoning

Các rule này không flag bằng pattern thuần. Agent vẫn phải trace L1-L4:

1. L1: route/query/body/header/form/file upload được ASP.NET Core bind tự động.
2. Sink: raw SQL, entity update, unsafe deserializer, process execution.
3. Sanitization/mitigation: parameterized EF/ADO.NET, DTO allowlist, safe serializer config, list-form arguments / whitelist.
4. Chỉ report khi input untrusted đi tới sink mà không có kiểm soát phù hợp.
