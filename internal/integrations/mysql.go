package integrations

import (
	"context"
	"database/sql"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-sql-driver/mysql"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// DefaultMySQLSockets are where MySQL and MariaDB packages put their socket.
var DefaultMySQLSockets = []string{"/run/mysqld/mysqld.sock", "/var/run/mysqld/mysqld.sock", "/var/lib/mysql/mysql.sock", "/tmp/mysql.sock"}

// MySQL reads MySQL/MariaDB status: connections, threads, queries, slow
// queries, InnoDB buffer pool efficiency and lock waits, replication, and
// (hourly) the size of each database.
//
// Without a DSN it connects over the local socket as the agent's OS user,
// which works once the database has a matching account authenticated by the
// socket and allowed to read status, e.g. on MariaDB:
//
//	CREATE USER 'yomins-agent'@'localhost' IDENTIFIED VIA unix_socket;
//	GRANT SLAVE MONITOR ON *.* TO 'yomins-agent'@'localhost'; -- MySQL: REPLICATION CLIENT
//
// The account reads no data: status and variables need no grant, the grant
// is for replication status, and database sizes come from the data
// directory. No password is stored anywhere.
type MySQL struct {
	dsn     string
	user    string
	sockets []string

	mu        sync.Mutex
	db        *sql.DB
	sizesAt   time.Time
	sizes     []metrics.MetricPoint
	sizeEvery time.Duration
}

// NewMySQL creates the integration; dsn (go-sql-driver format) overrides the socket login.
func NewMySQL(dsn, osUser string) *MySQL {
	return &MySQL{dsn: dsn, user: osUser, sockets: DefaultMySQLSockets, sizeEvery: time.Hour}
}

func (m *MySQL) Name() string { return "mysql" }

// statusVars maps SHOW GLOBAL STATUS variables to metrics; counters end in _total.
var statusVars = map[string][2]string{
	"Threads_connected":                {"mysql_threads_connected", "Open connections"},
	"Threads_running":                  {"mysql_threads_running", "Threads executing a query"},
	"Max_used_connections":             {"mysql_max_used_connections", "Most connections open at once since start"},
	"Connections":                      {"mysql_connections_total", "Connection attempts"},
	"Aborted_connects":                 {"mysql_aborted_connects_total", "Failed connection attempts"},
	"Aborted_clients":                  {"mysql_aborted_clients_total", "Connections dropped without closing"},
	"Questions":                        {"mysql_queries_total", "Statements sent by clients"},
	"Slow_queries":                     {"mysql_slow_queries_total", "Queries slower than long_query_time"},
	"Created_tmp_disk_tables":          {"mysql_tmp_disk_tables_total", "Temporary tables created on disk"},
	"Table_locks_waited":               {"mysql_table_locks_waited_total", "Table lock requests that had to wait"},
	"Innodb_buffer_pool_read_requests": {"mysql_innodb_buffer_pool_read_requests_total", "Logical reads from the buffer pool"},
	"Innodb_buffer_pool_reads":         {"mysql_innodb_buffer_pool_disk_reads_total", "Reads the buffer pool could not serve (went to disk)"},
	"Innodb_row_lock_waits":            {"mysql_innodb_row_lock_waits_total", "Row locks waited for"},
	"Innodb_row_lock_time":             {"mysql_innodb_row_lock_time_ms_total", "Time spent waiting for row locks, ms"},
	"Innodb_deadlocks":                 {"mysql_innodb_deadlocks_total", "Deadlocks (MariaDB)"},
	"Bytes_received":                   {"mysql_received_bytes_total", "Bytes received from clients"},
	"Bytes_sent":                       {"mysql_sent_bytes_total", "Bytes sent to clients"},
	"Uptime":                           {"mysql_uptime_seconds", "Seconds since the server started"},
	"Innodb_buffer_pool_pages_dirty":   {"mysql_innodb_buffer_pool_pages_dirty", "Dirty pages in the buffer pool"},
	"Innodb_buffer_pool_pages_total":   {"mysql_innodb_buffer_pool_pages_total", "Pages in the buffer pool"},
	"Innodb_buffer_pool_pages_free":    {"mysql_innodb_buffer_pool_pages_free", "Free pages in the buffer pool"},
	"Open_tables":                      {"mysql_open_tables", "Tables open"},
	"Opened_tables":                    {"mysql_opened_tables_total", "Tables opened (a fast rise means table_open_cache is too small)"},
}

var commands = []string{"select", "insert", "update", "delete", "replace", "commit", "rollback"}

func (m *MySQL) open() (*sql.DB, string, error) {
	if m.db != nil {
		return m.db, "", nil
	}
	dsn := m.dsn
	if dsn == "" {
		sock := ""
		for _, s := range m.sockets {
			if _, err := os.Stat(s); err == nil {
				sock = s
				break
			}
		}
		if sock == "" {
			return nil, "", nil // not installed here
		}
		cfg := mysql.NewConfig()
		cfg.User, cfg.Net, cfg.Addr = m.user, "unix", sock
		cfg.Timeout, cfg.ReadTimeout = 3*time.Second, 10*time.Second
		dsn = cfg.FormatDSN()
	}
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, dsn, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(10 * time.Minute)
	m.db = db
	return db, dsn, nil
}

func (m *MySQL) Collect(ctx context.Context) ([]metrics.MetricPoint, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	db, _, err := m.open()
	if db == nil && err == nil {
		return nil, nil
	}
	if err != nil {
		return []metrics.MetricPoint{status("mysql", StatusError, "")}, nil
	}
	rows, err := db.QueryContext(ctx, "SHOW GLOBAL STATUS")
	if err != nil {
		state := StatusError
		var me *mysql.MySQLError
		if asMySQLError(err, &me) && (me.Number == 1045 || me.Number == 1698) {
			state = StatusUnconfigured // the account for the agent does not exist yet
		}
		return []metrics.MetricPoint{status("mysql", state, ""), gauge("mysql_up", "1 when the agent could read the server's status", 0, nil)}, nil
	}
	var pts []metrics.MetricPoint
	for rows.Next() {
		var name, value string
		if rows.Scan(&name, &value) != nil {
			continue
		}
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			continue
		}
		if mm, ok := statusVars[name]; ok {
			if strings.HasSuffix(mm[0], "_total") {
				pts = append(pts, counter(mm[0], mm[1], v, nil))
			} else {
				pts = append(pts, gauge(mm[0], mm[1], v, nil))
			}
			continue
		}
		if c, ok := strings.CutPrefix(name, "Com_"); ok && contains(commands, c) {
			pts = append(pts, counter("mysql_commands_total", "Statements executed, by kind", v, map[string]string{"command": c}))
		}
	}
	rows.Close()

	var name string
	var maxConn float64
	if db.QueryRowContext(ctx, "SHOW GLOBAL VARIABLES LIKE 'max_connections'").Scan(&name, &maxConn) == nil {
		pts = append(pts, gauge("mysql_max_connections", "Connection limit", maxConn, nil))
	}
	pts = append(pts, m.replication(ctx, db)...)
	pts = append(pts, m.databaseSizes(ctx, db)...)
	pts = append(pts, gauge("mysql_up", "1 when the agent could read the server's status", 1, nil), status("mysql", StatusOK, ""))
	return pts, nil
}

// replication reports a replica's state; nothing on a primary.
func (m *MySQL) replication(ctx context.Context, db *sql.DB) []metrics.MetricPoint {
	rows, err := db.QueryContext(ctx, "SHOW SLAVE STATUS")
	if err != nil {
		return nil
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	if !rows.Next() {
		return nil
	}
	vals := make([]sql.NullString, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	if rows.Scan(ptrs...) != nil {
		return nil
	}
	get := map[string]sql.NullString{}
	for i, c := range cols {
		get[c] = vals[i]
	}
	yes := func(k string) float64 {
		if get[k].String == "Yes" {
			return 1
		}
		return 0
	}
	pts := []metrics.MetricPoint{
		gauge("mysql_replica_io_running", "1 when the replica's I/O thread runs", yes("Slave_IO_Running"), nil),
		gauge("mysql_replica_sql_running", "1 when the replica's SQL thread runs", yes("Slave_SQL_Running"), nil),
	}
	if lag := get["Seconds_Behind_Master"]; lag.Valid {
		v, _ := strconv.ParseFloat(lag.String, 64)
		pts = append(pts, gauge("mysql_replica_lag_seconds", "How far the replica is behind", v, nil))
	}
	return pts
}

// databaseSizes reports the 20 largest databases, hourly, from the size of
// their directories in the data directory: information_schema would need
// a grant on the tables themselves, i.e. on the data.
func (m *MySQL) databaseSizes(ctx context.Context, db *sql.DB) []metrics.MetricPoint {
	if !m.sizesAt.IsZero() && time.Since(m.sizesAt) < m.sizeEvery {
		return m.sizes
	}
	m.sizesAt = time.Now()
	var datadir string
	if err := db.QueryRowContext(ctx, "SELECT @@datadir").Scan(&datadir); err != nil || datadir == "" {
		m.sizes = nil
		return nil
	}
	m.sizes = dirSizes(datadir, 20)
	return m.sizes
}

// systemSchemas are left out of the database sizes.
var systemSchemas = map[string]bool{"mysql": true, "performance_schema": true, "sys": true, "information_schema": true}

func dirSizes(datadir string, top int) []metrics.MetricPoint {
	entries, err := os.ReadDir(datadir)
	if err != nil {
		return nil
	}
	type sized struct {
		name string
		size int64
	}
	var all []sized
	for _, e := range entries {
		if !e.IsDir() || systemSchemas[e.Name()] || strings.HasPrefix(e.Name(), "#") || strings.HasPrefix(e.Name(), ".") {
			continue
		}
		var total int64
		_ = filepath.WalkDir(filepath.Join(datadir, e.Name()), func(_ string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				if fi, err := d.Info(); err == nil {
					total += fi.Size()
				}
			}
			return nil
		})
		// Directory names encode special characters (@002d for "-").
		all = append(all, sized{decodeSchemaName(e.Name()), total})
	}
	sort.Slice(all, func(i, j int) bool { return all[i].size > all[j].size })
	var pts []metrics.MetricPoint
	for _, s := range all[:min(top, len(all))] {
		pts = append(pts, gauge("mysql_database_size_bytes", "Size of a database's files in the data directory", float64(s.size), map[string]string{"database": s.name}))
	}
	return pts
}

// decodeSchemaName turns MySQL's file name encoding (@002d) back into characters.
func decodeSchemaName(n string) string {
	var b strings.Builder
	for i := 0; i < len(n); i++ {
		if n[i] == '@' && i+4 < len(n) {
			if v, err := strconv.ParseUint(n[i+1:i+5], 16, 32); err == nil {
				b.WriteRune(rune(v))
				i += 4
				continue
			}
		}
		b.WriteByte(n[i])
	}
	return b.String()
}

func asMySQLError(err error, target **mysql.MySQLError) bool {
	me, ok := err.(*mysql.MySQLError)
	if ok {
		*target = me
	}
	return ok
}

func contains(vs []string, v string) bool {
	for _, x := range vs {
		if x == v {
			return true
		}
	}
	return false
}
