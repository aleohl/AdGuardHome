package querylog

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"os"
	"time"

	"github.com/AdguardTeam/golibs/logutil/slogutil"
	_ "github.com/go-sql-driver/mysql"
)

// mysqlClient is a client for writing query log entries to MySQL.
type mysqlClient struct {
	db       *sql.DB
	logger   *slog.Logger
	hostname string
}

// createTableSQL is the SQL statement for creating the query_log table.
const createTableSQL = `
CREATE TABLE IF NOT EXISTS query_log (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    time DATETIME(6) NOT NULL,
    server_hostname VARCHAR(255) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    client_id VARCHAR(255),
    client_proto VARCHAR(20) NOT NULL,
    query_host VARCHAR(255) NOT NULL,
    query_type VARCHAR(10) NOT NULL,
    query_class VARCHAR(10) NOT NULL,
    upstream VARCHAR(255),
    elapsed_ns BIGINT NOT NULL,
    cached BOOLEAN DEFAULT FALSE,
    authenticated_data BOOLEAN DEFAULT FALSE,
    ecs VARCHAR(50),
    answer MEDIUMBLOB,
    orig_answer MEDIUMBLOB,
    is_filtered BOOLEAN DEFAULT FALSE,
    filter_reason SMALLINT,
    filter_rule TEXT,
    service_name VARCHAR(100),
    result_json TEXT,

    INDEX idx_time (time),
    INDEX idx_server_hostname (server_hostname),
    INDEX idx_client_ip (client_ip),
    INDEX idx_query_host (query_host),
    INDEX idx_filtered (is_filtered)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
`

// insertSQL is the SQL statement for inserting a log entry.
const insertSQL = `
INSERT INTO query_log (
    time, server_hostname, client_ip, client_id, client_proto, query_host,
    query_type, query_class, upstream, elapsed_ns, cached, authenticated_data,
    ecs, answer, orig_answer, is_filtered, filter_reason, filter_rule,
    service_name, result_json
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

// newMySQLClient creates a new MySQL client and initializes the database table.
func newMySQLClient(ctx context.Context, logger *slog.Logger, dsn string) (c *mysqlClient, err error) {
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, err
	}

	defer func() {
		if err != nil {
			_ = db.Close()
		}
	}()

	// Configure connection pool
	db.SetMaxOpenConns(10)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Test connection
	err = db.PingContext(ctx)
	if err != nil {
		return nil, err
	}

	// Create table if not exists
	_, err = db.ExecContext(ctx, createTableSQL)
	if err != nil {
		return nil, err
	}

	// Get the server hostname
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	logger.InfoContext(ctx, "mysql client initialized successfully", "hostname", hostname)

	return &mysqlClient{
		db:       db,
		logger:   logger,
		hostname: hostname,
	}, nil
}

// add inserts a log entry into MySQL asynchronously.
func (c *mysqlClient) add(ctx context.Context, entry *logEntry) {
	go func() {
		err := c.insertEntry(ctx, entry)
		if err != nil {
			c.logger.ErrorContext(ctx, "inserting entry to mysql", slogutil.KeyError, err)
		}
	}()
}

// insertEntry performs the actual insert operation.
func (c *mysqlClient) insertEntry(ctx context.Context, entry *logEntry) error {
	var filterReason *int
	var filterRule *string
	var serviceName *string

	if entry.Result.IsFiltered {
		reason := int(entry.Result.Reason)
		filterReason = &reason

		if len(entry.Result.Rules) > 0 {
			rule := entry.Result.Rules[0].Text
			filterRule = &rule
		}

		if entry.Result.ServiceName != "" {
			serviceName = &entry.Result.ServiceName
		}
	}

	// Serialize the full Result as JSON for completeness
	resultJSON, err := json.Marshal(entry.Result)
	if err != nil {
		resultJSON = []byte("{}")
	}

	_, err = c.db.ExecContext(ctx, insertSQL,
		entry.Time,
		c.hostname,
		entry.IP.String(),
		nullString(entry.ClientID),
		string(entry.ClientProto),
		entry.QHost,
		entry.QType,
		entry.QClass,
		nullString(entry.Upstream),
		entry.Elapsed.Nanoseconds(),
		entry.Cached,
		entry.AuthenticatedData,
		nullString(entry.ReqECS),
		entry.Answer,
		entry.OrigAnswer,
		entry.Result.IsFiltered,
		filterReason,
		filterRule,
		serviceName,
		string(resultJSON),
	)

	return err
}

// nullString returns nil if s is empty, otherwise returns a pointer to s.
func nullString(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// close closes the MySQL database connection.
func (c *mysqlClient) close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}
