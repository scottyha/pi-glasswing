# PostgreSQL Vulnerability Patterns

Security patterns specific to PostgreSQL usage in web applications. Use as a checklist during Phase 2 (Vulnerability Search).

---

## 1. SQL Injection

### Pattern: String Interpolation in Queries

**What to search for:**
```bash
# String interpolation / template literals in SQL
grep -rn "query\|execute\|raw\|sql" --include="*.ts" --include="*.js" src/ | grep -E '\$\{|`.*SELECT|`.*INSERT|`.*UPDATE|`.*DELETE|\+.*SELECT|\+.*INSERT'

# Format string patterns
grep -rn "format\|sprintf\|%s.*SELECT\|%s.*INSERT" --include="*.ts" --include="*.js" src/

# String concatenation in queries
grep -rn '"SELECT\|"INSERT\|"UPDATE\|"DELETE' --include="*.ts" --include="*.js" src/ | grep "+"
```

**Vulnerable:**
```javascript
const result = await pool.query(`SELECT * FROM qualifications WHERE code = '${code}'`);
const result = await pool.query("SELECT * FROM users WHERE email = '" + email + "'");
```

**Safe:**
```javascript
const result = await pool.query('SELECT * FROM qualifications WHERE code = $1', [code]);
const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
```

**Verification:**
- Does the interpolated value come from user input? (URL params, form fields, chat messages)
- Is there any validation/sanitization before interpolation?
- Can the interpolation be bypassed? (Unicode tricks, encoding, null bytes)

### Pattern: Dynamic Table/Column Names

**What to search for:**
```bash
# Dynamic identifiers in SQL
grep -rn "FROM.*\$\|SELECT.*\$\|WHERE.*\$" --include="*.ts" --include="*.js" src/ | grep -v "\$1\|\$2\|\$3\|\$4\|\$5"
```

**Vulnerable:** Parameterized queries protect values but NOT identifiers (table names, column names). Dynamic table/column names must be whitelisted.

```javascript
// VULNERABLE: $1 doesn't protect table names
const result = await pool.query(`SELECT * FROM ${tableName} WHERE id = $1`, [id]);
```

**Safe:**
```javascript
const allowedTables = ['qualifications', 'industries', 'trade_licences'];
if (!allowedTables.includes(tableName)) throw new Error('Invalid table');
const result = await pool.query(`SELECT * FROM ${tableName} WHERE id = $1`, [id]);
```

---

## 2. Privilege Escalation

### Pattern: Over-Privileged Database Users

**What to search for:**
```bash
# Check GRANT statements in migration files
grep -rn "GRANT\|CREATE USER\|ALTER USER" --include="*.sql" .

# Check which DB user each connection uses
grep -rn "DATABASE_URL\|DB_USER\|DB_PASSWORD\|pool\|createPool" --include="*.ts" --include="*.js" --include=".env*" .
```

**Verify:**
- Does the public-facing app use the same DB user as admin features?
- Does the chat agent's restricted user (`rplit_public`) actually have restricted permissions?
- Can the app DB user modify schema, create tables, or access unrelated databases?

**Check actual permissions:**
```sql
-- What does rplit_public have access to?
SELECT grantee, table_name, privilege_type 
FROM information_schema.table_privileges 
WHERE grantee = 'rplit_public';

-- What schemas can it see?
SELECT nspname FROM pg_namespace WHERE has_schema_privilege('rplit_public', nspname, 'USAGE');
```

**Vulnerable:** Public API route connects as `rplit_admin` instead of `rplit_public`. One SQLi in a public endpoint gives full DB access.

**Safe:** Each endpoint uses the minimum-privilege user needed. Public routes use `rplit_public` (SELECT on specific tables only).

### Pattern: Connection String in Client Bundle

**What to search for:**
```bash
# Database URLs in client-accessible code
grep -rn "DATABASE_URL\|postgresql://" --include="*.ts" --include="*.tsx" --include="*.js" src/ | grep -v "api\|server\|route"
```

**Vulnerable:** Database connection string imported in a client component or available via `NEXT_PUBLIC_` env var.

**Safe:** Database connections only in server components, API routes, and server-only utility files.

---

## 3. pgvector Abuse

### Pattern: Embedding Manipulation

**What to search for:**
```bash
# Vector search queries
grep -rn "embedding\|vector\|cosine\|similarity\|<->\|=>\|1 - (" --include="*.ts" --include="*.js" src/
```

**Vulnerable:** If an attacker can influence what gets embedded (e.g., submitting qualification descriptions that get embedded into pgvector), they can manipulate search results. Not SQL injection per se, but content poisoning that skews the chat agent's recommendations.

**Safe:** Embeddings are generated from authoritative data (TGA sync), not from user-submitted content.

### Pattern: Vector Query Injection

**What to search for:**
```bash
# How are embeddings generated for search?
grep -rn "embed\|generateEmbedding\|embedding" --include="*.ts" --include="*.js" src/ | grep -i "query\|search\|user\|input"
```

**Vulnerable:** User input is concatenated into the embedding generation call, or the embedding result is used in a string-interpolated query.

**Safe:** User input goes through Gemini's embedding API (which handles sanitization), and the resulting vector is passed as a parameterized query value.

---

## 4. Connection Pool Exhaustion

### Pattern: Unclosed Connections

**What to search for:**
```bash
# Direct pool.query calls without error handling
grep -rn "pool\.query\|client\.query" --include="*.ts" --include="*.js" src/ | grep -v "try\|catch\|finally"

# Manual client checkout without release
grep -rn "pool\.connect\|getClient" --include="*.ts" --include="*.js" src/ | head -20
```

**Vulnerable:**
```javascript
const client = await pool.connect();
const result = await client.query('SELECT...');
// No client.release() — connection leaks
```

**Safe:**
```javascript
const client = await pool.connect();
try {
  const result = await client.query('SELECT...');
} finally {
  client.release();
}
```

**Impact:** DoS — connection pool exhausted, app becomes unresponsive.

---

## 5. Data Exposure Through Over-Broad Queries

### Pattern: SELECT * Leaking Sensitive Columns

**What to search for:**
```bash
# SELECT * queries
grep -rn "SELECT \*" --include="*.ts" --include="*.js" src/
```

**Vulnerable:** `SELECT * FROM rto_contacts` — returns addresses, phone numbers, emails that shouldn't be in the API response.

**Safe:** Explicit column selection:
```javascript
const result = await pool.query('SELECT name, code, level FROM qualifications WHERE...');
```

### Pattern: Missing Row-Level Filtering

**What to search for:**
```bash
# Queries without WHERE clauses or with overly broad WHERE
grep -rn "SELECT.*FROM" --include="*.ts" --include="*.js" src/ | grep -v "WHERE"
```

**Vulnerable:** API endpoint returns all records when it should return only the user's records, or only published records, or only records for the user's organisation.

**Safe:** Every query includes appropriate filtering based on the authenticated user's context.

---

## 6. Transaction Safety

### Pattern: Race Conditions in Lead Capture

**What to search for:**
```bash
# INSERT operations that should be unique
grep -rn "INSERT INTO.*chat_leads\|INSERT INTO.*leads" --include="*.ts" --include="*.js" src/
```

**Vulnerable:** Lead submission without unique constraint → duplicate leads created under concurrent requests. Or: check-then-insert without transaction → TOCTOU.

**Safe:** Use `INSERT ... ON CONFLICT DO NOTHING` or wrap check+insert in a transaction with appropriate isolation level.

---

## Quick Detection Commands

```bash
# ALL string interpolation in SQL contexts
grep -rn "query\|execute\|raw" --include="*.ts" --include="*.js" src/ | grep -E '\$\{|`' | head -30

# ALL database connection configurations
grep -rn "createPool\|new Pool\|DATABASE_URL" --include="*.ts" --include="*.js" --include=".env*" .

# ALL DB users referenced in code
grep -rn "rplit_public\|rplit_admin\|rplit_app\|DB_USER" --include="*.ts" --include="*.js" --include=".env*" .

# SELECT * usage
grep -rn "SELECT \*" --include="*.ts" --include="*.js" src/

# Missing error handling on DB calls
grep -rn "await.*\.query" --include="*.ts" --include="*.js" src/ | grep -v "try\|catch"
```