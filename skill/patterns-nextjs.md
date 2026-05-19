# Next.js Vulnerability Patterns

Security patterns specific to Next.js applications. Use as a checklist during Phase 2 (Vulnerability Search).

---

## 1. API Route Authentication

### Pattern: Missing Auth Check

**What to search for:**
```bash
# Find all API routes
find . -path '*/api/*' -name 'route.ts' -o -name 'route.js'

# Check which ones import auth/session utilities
grep -rL "getSession\|getServerSession\|withAuth\|requireAuth\|useAuth" --include="route.ts" --include="route.js" src/app/api/
```

**Vulnerable:** API route that handles sensitive data but has no auth check.

**Safe:** Every sensitive route checks session or uses auth middleware.

**Verification:**
- Is the route meant to be public? (e.g., `/api/public-chat`)
- If public, does it handle untrusted input safely?
- If meant to be protected, is auth enforced at the route level or only in middleware?

### Pattern: Middleware Bypass

**What to search for:**
```bash
# Check middleware configuration
cat src/middleware.ts

# Check for matcher patterns that might exclude routes
grep -r "matcher\|config" src/middleware.ts
```

**Vulnerable:**
- Middleware protects `/admin/*` but admin route is at `/api/admin-data` (different path prefix)
- Middleware uses regex that can be bypassed with path encoding (`%2e`, `%2f`)
- Route is excluded from middleware via matcher config

**Safe:** Auth is checked at the route level AND in middleware (defense in depth).

### Pattern: Server Component Data Leak

**What to search for:**
```bash
# Server components that pass sensitive data to client components
grep -rn "export default\|function.*Page" --include="*.tsx" src/app/ | head -50
# Then check what props are passed to client components
grep -rn "clientComponent\|ClientComponent\|<Client" --include="*.tsx" src/
```

**Vulnerable:** Server component fetches full user record, passes entire object as prop to client component. Client component renders subset but full object is in the HTML/serialized RSC payload.

**Safe:** Server component selects only needed fields before passing to client.

---

## 2. Environment Variable Exposure

### Pattern: Client-Exposed Secrets

**What to search for:**
```bash
# Next.js only exposes NEXT_PUBLIC_ prefixed vars to the client
grep -rn "NEXT_PUBLIC_" --include="*.ts" --include="*.tsx" --include="*.env*" .

# Check for secrets in non-NEXT_PUBLIC vars that might leak
grep -rn "API_KEY\|SECRET\|PASSWORD\|TOKEN\|PRIVATE" .env* 2>/dev/null
```

**Vulnerable:**
- `NEXT_PUBLIC_API_KEY=sk_live_...` — exposed in client bundle
- Secret used in a client component (even without NEXT_PUBLIC_ prefix, if it's imported in a `'use client'` file, Next.js may bundle it)

**Safe:** All secrets use server-only env vars (no NEXT_PUBLIC_ prefix) and are only accessed in server components / API routes.

**Verification:** Check the built client bundle for leaked secrets:
```bash
grep -r "sk_\|pk_live_\|AKIA" .next/static/
```

### Pattern: Fallback Default Secrets (Fail-Open)

**What to search for:**
```bash
# Fallback values for secrets
grep -rn "process\.env\.[A-Z_]* ||\|process\.env\.[A-Z_]* ??\|?.*'\"\|]?.*'" --include="*.ts" --include="*.js" .
# More specific:
grep -rn "process\.env\.\w* *|| *['\"]" --include="*.ts" --include="*.js" .
```

**Vulnerable:**
```javascript
const SECRET = process.env.JWT_SECRET || 'default-secret';
const API_KEY = process.env.API_KEY ?? 'dev-key-123';
```
App runs with weak secret if env var is missing. This is a **fail-open** pattern.

**Safe:**
```javascript
const SECRET = process.env.JWT_SECRET; // undefined → app crashes or throws
if (!SECRET) throw new Error('JWT_SECRET required');
```

---

## 3. Server Actions

### Pattern: Unvalidated Server Action Input

**What to search for:**
```bash
# Find all server actions
grep -rln "use server" --include="*.ts" --include="*.tsx" .

# Check for input validation (zod, valibot, manual checks)
grep -rn "use server" --include="*.tsx" -A 5 | grep -v "zod\|valibot\|schema\|validate\|parse"
```

**Vulnerable:** Server action accepts raw form data without validation. Anyone can POST arbitrary fields.

**Safe:** Server action validates input with a schema (zod, valibot) before processing.

### Pattern: Server Action Without Auth

**What to search for:**
```bash
# Server actions that modify data without auth checks
grep -rln "use server" --include="*.tsx" | xargs grep -L "getSession\|getServerSession\|auth"
```

**Vulnerable:** Server action creates/updates/deletes data but doesn't verify the user is authenticated.

**Safe:** Every mutating server action verifies auth before executing.

---

## 4. SSR/SSG Data Exposure

### Pattern: Error Messages Leaking Internal State

**What to search for:**
```bash
# API routes that return raw error messages
grep -rn "catch.*error\|\.message\|error\.stack" --include="route.ts" --include="route.js" src/app/api/
```

**Vulnerable:**
```javascript
catch (err) {
  return Response.json({ error: err.message }); // Leaks DB query, table names, stack trace
}
```

**Safe:**
```javascript
catch (err) {
  console.error(err); // Log internally
  return Response.json({ error: 'Internal server error' }); // Generic to client
}
```

### Pattern: Debug Info in Production

**What to search for:**
```bash
# Next.js debug/dev mode checks
grep -rn "NODE_ENV\|debug\|dev\|verbose" --include="*.ts" --include="*.tsx" src/ | grep -v "node_modules\|.next"
```

**Vulnerable:** Stack traces, query logs, or debug endpoints enabled in production.

**Safe:** Debug features gated on `NODE_ENV !== 'production'`.

---

## 5. Dynamic Route Injection

### Pattern: Path Traversal via Dynamic Segments

**What to search for:**
```bash
# Dynamic route segments
grep -rn "params\.\|searchParams\." --include="page.tsx" --include="route.ts" src/app/
```

**Vulnerable:**
```javascript
// Using user-supplied slug directly in filesystem or DB query
const content = fs.readFileSync(`content/${params.slug}.md`);
```

**Safe:**
```javascript
// Validate slug format before use
if (!/^[a-z0-9-]+$/.test(params.slug)) {
  return notFound();
}
```

### Pattern: Open Redirect

**What to search for:**
```bash
# Redirects using user input
grep -rn "redirect\|Response\.redirect\|push\|replace" --include="*.ts" --include="*.tsx" src/ | grep -i "param\|query\|search"
```

**Vulnerable:** `redirect(searchParams.returnUrl)` — attacker controls destination.

**Safe:** Whitelist allowed redirect destinations or use relative paths only.

---

## 6. Image Optimization Abuse

### Pattern: SSRF via Next.js Image Loader

**What to search for:**
```bash
# Image optimization config
cat next.config.js | grep -A 10 "images"
```

**Vulnerable:** `images.domains` includes internal hostnames (database-server, rplit-db, etc.). Attacker can use `_next/image?url=http://internal-host:port/` to probe internal network.

**Safe:** `images.domains` only includes public CDN/domains. Internal resources use direct URLs, not the image optimizer.

---

## Quick Detection Commands

```bash
# All API routes without auth imports
find src/app/api -name "route.ts" -exec grep -L "getSession\|auth\|session" {} \;

# All env vars with fallback defaults
grep -rn "process\.env\.\w* *||\|process\.env\.\w* *??" --include="*.ts" --include="*.js" src/

# Server actions without validation
grep -rln "use server" --include="*.tsx" | xargs grep -L "zod\|schema\|validate\|parse"

# Client components importing server-only modules
grep -rn "'use client'" --include="*.tsx" -A 20 | grep "import.*fs\|import.*child_process\|import.*crypto"

# Dynamic routes using params without validation
grep -rn "params\." --include="page.tsx" src/app/ | grep -v "notFound\|validate\|test\|regex"
```