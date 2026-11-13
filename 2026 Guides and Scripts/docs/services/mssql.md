# SQL Server Guide — 2019 MSSQL

Candidate service (packet role: "SQL; instance, authentication mode and application dependencies unconfirmed"). The scoring check involves application/database dependencies behind HTTP or mail scoring. Packet p.14 leaves precise scored services to the event portal. Windows Server 2019 Standard, 172.20.240.120.

## Discovery

> **Status:** candidate service — the packet lists this as a possible scored service but does not confirm it on any specific host. Verify on the live system before relying on any step below.

Confirm SQL Server is installed, running, and discover the instance name and port:

```powershell
# SQL Server service (default instance)
Get-Service MSSQLSERVER | Select-Object Status, StartType
# Named instances
Get-WmiObject Win32_Service | Where-Object { $_.Name -like 'MSSQL$%' } | Select-Object Name, State, StartMode
# Or via registry
Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\Instance Names\SQL" 2>$null
# SQL Agent
Get-Service SQLSERVERAGENT | Select-Object Status, StartType
# Listening ports
netstat -an | findstr ":1433\|:1434"
# SQL Browser (for named instances)
Get-Service SQLBrowser | Select-Object Status
```

From a client (Kali or Rocky Ecom):

```bash
# Test connectivity
python3 -c "
import socket
s = socket.socket(); s.settimeout(5)
try:
    s.connect(('172.20.240.120', 1433))
    print('Port 1433: OPEN')
except: print('Port 1433: closed/filtered')
finally: s.close()
"
# If sqlcmd or pyodbc is available
python3 -c "import pyodbc; c=pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=172.20.240.120;DATABASE=master;Trusted_Connection=yes'); print(c.execute('SELECT @@VERSION').fetchone())"
```

## Setup

SQL Server is pre-installed on Windows Server 2019. Do not reinstall. If the service is stopped:

```powershell
Start-Service MSSQLSERVER
Set-Service MSSQLSERVER -StartupType Automatic
# SQL Agent (if needed)
Start-Service SQLSERVERAGENT
Set-Service SQLSERVERAGENT -StartupType Automatic
```

## Configuration

### Instance and authentication mode

- **Default instance**: TCP 1433, no instance name suffix.
- **Named instance**: dynamic port (discover via SQL Browser UDP 1434 or registry).
- **Authentication mode**: Windows Auth vs Mixed Mode (SQL + Windows). Discover before changing:
  ```powershell
  # Via SQL Server Management Studio or T-SQL
  -- Run in SSMS or sqlcmd
  SELECT SERVERPROPERTY('ServerName') AS server_name,
         SERVERPROPERTY('IsIntegratedSecurityOnly') AS windows_only;
  -- Check auth mode (requires sysadmin)
  -- In SSMS: right-click server → Properties → Security → Server authentication
  ```

### Databases

- Discover databases: `SELECT name, state_desc FROM sys.databases`
- The scored application likely uses a specific database. Confirm with the portal.
- Preserve all existing databases, users, and permissions.

### Firewall

Ensure the SQL port is reachable from the scoring path:

```powershell
netsh advfirewall firewall show rule name="SQL Server" | findstr "1433"
# If missing:
netsh advfirewall firewall add rule name="SQL Server TCP 1433" dir=in action=allow protocol=TCP localport=1433
```

For named instances, also open UDP 1434 (SQL Browser) or the specific dynamic port.

### Palo Alto / VyOS

Verify NAT and routing allow SQL traffic from the application server (Rocky Ecom or Ubuntu Email) to the MSSQL host. Check for any ACL blocking the SQL port.

PAN-OS CLI options (discovery only):

```
show running security-policy | match 172.20.240.120
show session all filter destination 172.20.240.120 destination-port 1433
show interface ethernet1/2
show zone
```

GUI equivalent: Policies > Security, Monitor > Traffic, Network > Interfaces.

## Monitoring

```powershell
# Service health
Get-Service MSSQLSERVER, SQLSERVERAGENT | Select-Object Name, Status
# Connection count
-- T-SQL
SELECT COUNT(*) AS open_connections FROM sys.dm_exec_sessions
# Disk usage
Get-Volume | Where-Object { $_.DriveLetter -eq 'C' } | Select-Object UsedSize, Size
# Error log (last 20 entries)
-- T-SQL
EXEC sp_readerrorlog 0, 1;
# Performance counters
Get-Counter '\SQLServer:General Statistics\Total Connections' -SampleInterval 5 -MaxSamples 3
```

Forward SQL Server error logs to Splunk if required. Verify at Quotient that the scored application can query the database.

## Backup

Back up SQL Server databases and configuration before any change:

Run T-SQL in SSMS or `sqlcmd`, not directly in PowerShell. Create a protected backup directory on an approved volume and grant the **SQL Server service identity** write access. Use a new filename per backup; do not overwrite the only known-good copy.

```sql
BACKUP DATABASE [master] TO DISK = 'E:\SQLBackup\master-<UTC>.bak' WITH CHECKSUM;
-- Repeat for msdb, model and each actual user database:
BACKUP DATABASE [<user_database>] TO DISK = 'E:\SQLBackup\userdb-<UTC>.bak' WITH CHECKSUM;
RESTORE VERIFYONLY FROM DISK = 'E:\SQLBackup\userdb-<UTC>.bak' WITH CHECKSUM;
```

`E:` is an example separate approved destination, not an assumed available drive. Check free space and backup completion messages. The Resource database (`mssqlsystemresource`) cannot be backed up with `BACKUP DATABASE`; follow the installed-version file backup procedure if needed. `master` has no transaction-log backup. For user databases in FULL/BULK_LOGGED recovery, coordinate log backups with the existing DBA chain; do not switch recovery models or break that chain.

`RESTORE VERIFYONLY` is not a restore rehearsal. Test restore on an isolated matching instance, with distinct database name and `WITH MOVE` paths for every logical file; never `WITH REPLACE` against a live scored database merely to test a backup. Protect copies off-host; no VM snapshots.

## Usage and scoring verification

Verify the scored application can connect and query:

```powershell
# From the application server (Rocky Ecom or Ubuntu Email)
-- T-SQL via sqlcmd or application connection string
SELECT TOP 5 * FROM [scored_database].[dbo].[scored_table]

# From Kali (if authorized)
python3 -c "
import pyodbc
c = pyodbc.connect('DRIVER={ODBC Driver 17 for SQL Server};SERVER=172.20.240.120;DATABASE=<db>;UID=<user>;PWD=<pass>')
print(c.execute('SELECT COUNT(*) FROM <table>').fetchone())
"
```

Test from both internal and public paths. Confirm Quotient shows the scored query returning expected data.

## Recovery

1. Identify the issue: service down, database offline, or application connection failure.
2. If service stopped: `Start-Service MSSQLSERVER`
3. If database offline: `ALTER DATABASE [<db>] SET ONLINE` (if possible) or restore from backup:
   ```sql
   RESTORE DATABASE [<db>] FROM DISK = 'C:\backup\sql-<db>-<timestamp>.bak' WITH REPLACE
   ```
4. If configuration is corrupted, compare the saved instance configuration and repair only confirmed differences; do not blindly import an entire SQL registry tree.
5. Verify with a test query from the application server.
6. Record UTC time and residual exposure.

## References

- [2019 MSSQL system guide](../systems/2019-mssql.md)
- [Environment constraints](../environment.md)
- [Event checklist](../event-checklist.md)
