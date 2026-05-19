# Infrastructure Vulnerability Patterns

Security patterns for nginx, security headers, CORS, TLS, and rate limiting. Use as a checklist during Phase 2 (Vulnerability Search).

---

## 1. Security Headers

### Pattern: Missing Security Headers

**What to search for (on the live site):**
```bash
# Fetch headers from the site
curl -sI https://rplit-preview.scott-roy.com | head -30

# Or test against any URL
curl -sI https://example.com | grep -i "strict-transport\|content-security\|x-frame\|x-content-type\|referrer-policy\|permissions-policy"
```

**Required headers and their purpose:**

| Header | Purpose | Missing = Risk |
|--------|---------|----------------|
| `Strict-Transport-Security` | Forces HTTPS | MEDIUM — user can be downgraded to HTTP |
| `Content-Security-Policy` | Controls resource loading | HIGH — XSS can load external scripts |
| `X-Frame-Options` | Prevents clickjacking | MEDIUM — page can be framed |
| `X-Content-Type-Options` | Prevents MIME sniffing | LOW — browser may execute non-HTML as HTML |
| `Referrer-Policy` | Controls referrer data | LOW — full URL leaked to third parties |
| `Permissions-Policy` | Restricts browser features | LOW — camera/mic/geolocation accessible |

**Verification:**
- Check headers on ALL response types (HTML pages, API responses, static assets)
- API responses need headers too (prevent XSS in JSON responses rendered as HTML)
- Verify headers are set in nginx config, not just Next.js (defense in depth)

### Pattern: Weak Content-Security-Policy

**What to search for:**
```bash
# CSP header in nginx config
grep -rn "Content-Security-Policy" /etc/nginx/ 2>/dev/null
# Or check response headers
curl -sI https://example.com | grep -i "content-security"
```

**Vulnerable:**
```
Content-Security-Policy: default-src *; script-src * 'unsafe-inline' 'unsafe-eval';
```
Wildcard sources + `unsafe-inline` + `unsafe-eval` = effectively no CSP.

**Safe:**
```
Content-Security-Policy: default-src 'self'; script-src 'self' https://cdn.example.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://generativelanguage.googleapis.com; frame-ancestors 'none';
```
Specific sources, no `unsafe-eval`, minimal `unsafe-inline` (style only).

**Next.js-specific:** Check if Next.js is setting its own CSP (via `next.config.js` headers or middleware). These may conflict with nginx.

---

## 2. CORS Configuration

### Pattern: Overly Permissive CORS

**What to search for:**
```bash
# CORS headers in nginx
grep -rn "Access-Control\|cors" /etc/nginx/ 2>/dev/null

# CORS in application code
grep -rn "Access-Control\|cors\|origin" --include="*.ts" --include="*.js" src/ | grep -i "allow\|origin\|header"
```

**Vulnerable:**
```
Access-Control-Allow-Origin: *
Access-Control-Allow-Credentials: true
```
This combination is actually blocked by browsers (good), but `Access-Control-Allow-Origin: *` without credentials still allows any site to read public API responses.

**More subtly vulnerable:**
```
Access-Control-Allow-Origin: https://attacker.com
Access-Control-Allow-Credentials: true
```
If the server reflects the `Origin` header without validation, any origin gets credentialed access.

**Safe:**
```
Access-Control-Allow-Origin: https://rplit.com.au
Access-Control-Allow-Credentials: true
```
Explicit, specific origin. No reflection.

**Verification:**
```bash
# Test if server reflects arbitrary origins
curl -sI -H "Origin: https://evil.com" https://example.com/api/endpoint | grep -i "access-control"
```

### Pattern: Missing CORS for Public API

**Vulnerable:** Public API endpoints (like `/api/public-chat`) that are meant to be called from the website don't have CORS configured at all → browser blocks the request → developer adds `*` as a quick fix.

**Safe:** Specific origin allowed, or the endpoint uses same-origin by default and doesn't need CORS.

---

## 3. TLS Configuration

### Pattern: Weak TLS Settings

**What to search for:**
```bash
# Nginx SSL configuration
grep -rn "ssl_\|tls\|protocols\|ciphers" /etc/nginx/ 2>/dev/null

# Or test with openssl
openssl s_client -connect example.com:443 -tls1_1 2>&1 | grep -i "protocol\|alert"
```

**Vulnerable:**
- TLS 1.0 or 1.1 enabled
- Weak cipher suites (RC4, DES, 3DES, EXPORT)
- No HSTS header

**Safe:**
- TLS 1.2+ only (prefer TLS 1.3)
- Strong cipher suites only (AEAD: AES-GCM, ChaCha20-Poly1305)
- HSTS with long max-age and includeSubDomains

**Note:** If behind Cloudflare, Cloudflare handles TLS termination. The Cloudflare → origin connection needs its own TLS check (Full Strict mode).

### Pattern: Mixed Content

**Vulnerable:** HTTPS page loads resources over HTTP (scripts, images, API calls). Browser blocks or warns.

**Safe:** All resources loaded over HTTPS. `upgrade-insecure-requests` CSP directive.

---

## 4. nginx Misconfiguration

### Pattern: Server Information Disclosure

**What to search for:**
```bash
# Check nginx version disclosure
curl -sI https://example.com | grep -i "server:"

# nginx config for server_tokens
grep -rn "server_tokens" /etc/nginx/ 2>/dev/null
```

**Vulnerable:** `Server: nginx/1.24.0` — reveals exact version, helps attackers find CVEs.

**Safe:** `server_tokens off;` in nginx config → `Server: nginx` (no version).

### Pattern: Sensitive Files Accessible

**What to search for:**
```bash
# Test for common sensitive file exposure
curl -s https://example.com/.env | head -5
curl -s https://example.com/.git/config | head -5
curl -s https://example.com/package.json | head -5
curl -s https://example.com/next.config.js | head -5
curl -s https://example.com/.next/ | head -5
```

**Vulnerable:** `.env`, `.git/`, `package.json`, or `.next/` directory accessible via web.

**Safe:** nginx explicitly denies these paths:
```nginx
location ~ /\. { deny all; }
location ~ /package\.json { deny all; }
location ~ /\.next { deny all; }
```

### Pattern: Missing Rate Limiting

**What to search for:**
```bash
# Rate limiting in nginx
grep -rn "limit_req\|limit_conn\|rate" /etc/nginx/ 2>/dev/null

# Rate limiting in application code
grep -rn "rate\|limit\|throttle" --include="*.ts" --include="*.js" src/ | grep -v "node_modules"
```

**Vulnerable:** No rate limiting on any endpoint. Attacker can:
- Brute-force admin login (if any)
- Flood chat endpoint (cost DoS via Gemini API)
- Spam lead capture form (database pollution)
- Scrape all qualification pages at high speed

**Safe:**
- nginx `limit_req_zone` for global rate limiting
- Per-endpoint rate limiting for sensitive operations
- Application-level rate limiting for API routes
- Cloudflare rate limiting as outer layer

### Pattern: Proxying Internal Services

**What to search for:**
```bash
# nginx proxy_pass directives
grep -rn "proxy_pass" /etc/nginx/ 2>/dev/null
```

**Vulnerable:** nginx proxies requests to internal services that shouldn't be web-accessible (e.g., database admin tools, internal APIs, metrics endpoints).

**Safe:** nginx only proxies to intended public services. Internal services are blocked by firewall (Tailscale-only) regardless of nginx config.

---

## 5. Cookie Security

### Pattern: Insecure Cookie Flags

**What to search for:**
```bash
# Cookie settings in application
grep -rn "cookie\|setCookie\|set.*cookie\|HttpOnly\|Secure\|SameSite" --include="*.ts" --include="*.js" src/ | grep -v "node_modules"

# Check actual cookies set by the site
curl -sI https://example.com | grep -i "set-cookie"
```

**Vulnerable:**
```
Set-Cookie: session=abc123
```
No `Secure` (sent over HTTP), no `HttpOnly` (accessible via JavaScript/XSS), no `SameSite` (sent on cross-site requests → CSRF).

**Safe:**
```
Set-Cookie: session=abc123; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=3600
```

**Verification:** Check ALL cookies set by the application (session, CSRF tokens, analytics).

---

## 6. Cloudflare Bypass

### Pattern: Origin IP Exposed

**What to search for:**
```bash
# DNS records that might expose the origin IP
dig example.com A
dig example.com AAAA
dig mail.example.com A
dig ftp.example.com A

# Historical DNS records (check security-audit-agent results)
```

**Vulnerable:** Any DNS record pointing directly to the VPS IP without Cloudflare proxy (grey cloud instead of orange). Or: the origin IP is discoverable through other means (SSL certificate search, historical DNS, email headers).

**Safe:** All DNS records proxied through Cloudflare. Origin IP not discoverable. Firewall blocks non-Cloudflare IPs on HTTP/HTTPS ports.

**Verification:**
- If the VPS firewall is currently Tailscale-only (no public HTTP/HTTPS), this is safe for now
- But check: will the firewall be opened for the domain cutover? If so, ensure it only accepts Cloudflare IPs
- Check the planned Cloudflare configuration: Full (Strict) SSL mode, minimum TLS 1.2

---

## Quick Detection Commands

```bash
# Full header audit
curl -sI https://example.com | grep -iE "strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy|server|x-powered"

# CORS test with arbitrary origin
curl -sI -H "Origin: https://evil.com" https://example.com/api/public-chat | grep -i access-control

# TLS version test
openssl s_client -connect example.com:443 -tls1 1>/dev/null 2>&1 | grep -E "Protocol|alert"

# Sensitive file exposure test
for path in .env .git/config .git/HEAD package.json .next/BUILD_ID; do
  status=$(curl -so /dev/null -w "%{http_code}" "https://example.com/$path")
  echo "$path → $status"
done

# nginx config review (on the VPS)
ssh rplit "grep -rn 'server_tokens\|limit_req\|proxy_pass\|ssl_\|Access-Control' /etc/nginx/"

# Cookie security audit
curl -sI https://example.com | grep -i "set-cookie" | grep -v "Secure\|HttpOnly\|SameSite"
```