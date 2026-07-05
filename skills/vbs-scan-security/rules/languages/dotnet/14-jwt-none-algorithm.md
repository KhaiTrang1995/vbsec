---
id: JWT-NONE-ALGORITHM
severity_max: CRITICAL
applies_to: dotnet
overrides: generic/14-jwt-none-algorithm.md
---

# JWT none Algorithm & Weak Secret — .NET 10 / ASP.NET Core Specialization

> Override cho rule chung `rules/generic/14-jwt-none-algorithm.md`. Áp dụng khi `primary_language: dotnet`.

## Intent (.NET-specific)

ASP.NET Core dùng `Microsoft.AspNetCore.Authentication.JwtBearer` + `System.IdentityModel.Tokens.Jwt` (`JwtSecurityTokenHandler`). Khác PyJWT/jsonwebtoken, thư viện .NET không mặc định chấp nhận `alg: none`, nhưng vibe code vẫn tạo ra lỗ hổng tương đương qua **`TokenValidationParameters` cấu hình sai**:

1. **`ValidateIssuerSigningKey = false`** hoặc thiếu hẳn field này — token với signature bất kỳ (kể cả rỗng) vẫn pass validate.
2. **`SignatureValidator`/`RequireSignedTokens = false`** custom override bỏ qua verify signature hoàn toàn.
3. **Secret/signing key hardcode hoặc quá ngắn**: `new SymmetricSecurityKey(Encoding.UTF8.GetBytes("secret"))`.
4. **Algorithm confusion RS256/HS256**: `ValidateIssuerSigningKey = true` nhưng `IssuerSigningKey` set là RSA public key trong khi handler chấp nhận cả `HS256` — attacker sign HS256 token dùng public key (ai cũng lấy được) làm HMAC secret.
5. **`ValidateLifetime = false`** — token hết hạn vẫn được chấp nhận vô thời hạn.

## Khi nào CRITICAL

- `TokenValidationParameters.ValidateIssuerSigningKey` thiếu hoặc `= false`.
- `RequireSignedTokens = false` hoặc `SignatureValidator = (token, parameters) => new JwtSecurityToken(token)` (bypass verify hoàn toàn).
- Signing key hardcode string ngắn: `new SymmetricSecurityKey(Encoding.UTF8.GetBytes("mysecretkey"))`, hoặc lấy từ `appsettings.json` default value yếu (`"Jwt:Key": "changeme"`).
- `ValidAlgorithms` (nếu set) chứa nhiều algorithm hỗn hợp cho cùng 1 key (`["HS256", "RS256"]`) — algorithm confusion.
- `JwtSecurityTokenHandler().ReadJwtToken(token)` dùng để đọc claims rồi tin tưởng cho authorization mà không qua `ValidateToken`.
- `ValidateIssuer = false` VÀ `ValidateAudience = false` cùng lúc — token issue từ service khác cũng được chấp nhận.

## Khi nào HIGH (giảm cấp)

- Secret yếu nhưng chỉ dùng trong `appsettings.Development.json`/test fixture, không phải config production thật.
- `ValidateLifetime = false` chỉ trong middleware test/tool nội bộ không expose public.
- Đọc claims bằng `ReadJwtToken` chỉ để hiển thị UI (không dùng cho authorization decision).

## Cách reasoning

1. Grep sink: `TokenValidationParameters`, `ValidateIssuerSigningKey`, `RequireSignedTokens`, `SignatureValidator`, `SymmetricSecurityKey`, `ReadJwtToken`.
2. Read cấu hình `AddJwtBearer(options => { options.TokenValidationParameters = ... })` — field nào bị tắt/thiếu?
3. Trace `IssuerSigningKey` từ đâu: `builder.Configuration["Jwt:Key"]` (check default fallback trong appsettings), hardcode string, hay load từ Key Vault/secret manager (an toàn hơn).
4. Kiểm tra `ValidAlgorithms` có mix HS/RS không nếu explicit set.
5. Cross-check `appsettings.json`/`appsettings.Production.json` — giá trị default có phải placeholder yếu (`"changeme"`, `"secret"`, `"your-256-bit-secret"`) không.

## Search patterns

```
# TokenValidationParameters thiếu/tắt validate signing key
TokenValidationParameters\s*\{[^}]*ValidateIssuerSigningKey\s*=\s*false
TokenValidationParameters\s*\{(?![^}]*ValidateIssuerSigningKey)[^}]*\}

# Bypass signature verify
RequireSignedTokens\s*=\s*false
SignatureValidator\s*=

# Hardcoded / weak key
SymmetricSecurityKey\s*\(\s*Encoding\.UTF8\.GetBytes\s*\(\s*["'][^"']{1,20}["']
["'](Jwt:Key|JwtSettings:Secret)["']\s*[,:]\s*["'](secret|changeme|your-256-bit-secret|test)["']

# Algorithm confusion
ValidAlgorithms\s*=\s*new(\[\]|List<string>)\s*\{[^}]*"HS256"[^}]*"RS256"

# Đọc claims không verify rồi dùng cho auth
ReadJwtToken\s*\(\s*token\s*\)(?!.*ValidateToken)

# Validate issuer + audience cùng tắt
ValidateIssuer\s*=\s*false[^;]*ValidateAudience\s*=\s*false
```

## Examples

### CRITICAL — flag

```csharp
// Thiếu ValidateIssuerSigningKey — signature bất kỳ đều pass
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true
            // KHÔNG có ValidateIssuerSigningKey → mặc định false trong 1 số version, luôn set rõ
        };
    });
```

```csharp
// Bypass verify hoàn toàn bằng custom validator
options.TokenValidationParameters.SignatureValidator =
    (token, parameters) => new JwtSecurityToken(token);  // không check signature gì cả
```

```csharp
// Secret hardcode ngắn
var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("mysecretkey"));  // CRITICAL, quá ngắn + hardcode
options.TokenValidationParameters.IssuerSigningKey = key;
```

```csharp
// appsettings.json — default value yếu
{
  "Jwt": {
    "Key": "your-256-bit-secret"  // giá trị mẫu từ tutorial, không đổi khi deploy prod
  }
}
```

```csharp
// Algorithm confusion — chấp nhận cả HS256 và RS256 cùng 1 key config
options.TokenValidationParameters.ValidAlgorithms = new[] { "HS256", "RS256" };
options.TokenValidationParameters.IssuerSigningKey = rsaPublicKey;  // public key dùng làm HMAC secret nếu attacker chọn HS256
```

```csharp
// Đọc claims không verify rồi tin tưởng cho authorization
var jwt = new JwtSecurityTokenHandler().ReadJwtToken(token);
var role = jwt.Claims.First(c => c.Type == "role").Value;
if (role == "Admin") { /* cấp quyền admin không verify signature */ }
```

### NOT critical — không flag

```csharp
// Cấu hình đầy đủ, đúng cách
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidateAudience = true,
            ValidAudience = builder.Configuration["Jwt:Audience"],
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),  // key ≥32 bytes, required từ config
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(1)
        };
    });
```

```csharp
// Key lấy từ Key Vault / secret manager, required (throw nếu thiếu)
var key = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key missing");
if (key.Length < 32) throw new InvalidOperationException("Jwt:Key too short");
```

```csharp
// RS256 chỉ dùng RS256, không mix
options.TokenValidationParameters.ValidAlgorithms = new[] { SecurityAlgorithms.RsaSha256 };
options.TokenValidationParameters.IssuerSigningKey = new RsaSecurityKey(rsaPublicKey);
```

## Fix recommendation

1. **Luôn set `ValidateIssuerSigningKey = true`** — không bao giờ bỏ qua field này.
2. **Không dùng `SignatureValidator` custom** trừ khi thực sự hiểu rủi ro — mặc định handler đã verify đúng.
3. **Key mạnh ≥32 bytes**, load từ config/secret manager (Azure Key Vault, AWS Secrets Manager), required — không default value:
   ```csharp
   var key = builder.Configuration["Jwt:Key"] ?? throw new InvalidOperationException("Jwt:Key required");
   ```
4. **Không mix algorithm** cho cùng 1 signing key — HS256 dùng symmetric key riêng, RS256 dùng asymmetric key riêng, không cross-accept.
5. **Verify đầy đủ**: `ValidateIssuer`, `ValidateAudience`, `ValidateLifetime` đều `true` với giá trị cụ thể (không wildcard).
6. **Không dùng `ReadJwtToken` cho authorization** — chỉ `ValidateToken`/pipeline `[Authorize]` chuẩn của framework mới đảm bảo signature đã verify.
7. **Rotation**: hỗ trợ multi-key qua `kid` header để đổi secret không downtime; asymmetric (RS256/ES256) khi có nhiều service cần verify nhưng chỉ 1 service issue token.

## Cross-references

- `01-hardcoded-secret`: JWT signing key hardcode = lộ → forge token toàn hệ thống.
- `12-broken-access-control`: JWT verify sai = bypass authentication/authorization toàn bộ.
- `15-cors-misconfig`: JWT lưu cookie + CORS `AllowAnyOrigin` + credentials = cross-origin token theft.
- `17-verbose-error-debug-mode`: Developer Exception Page lộ `Jwt:Key` từ config khi bind lỗi.
