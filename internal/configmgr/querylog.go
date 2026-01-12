package configmgr

import (
	"github.com/AdguardTeam/golibs/errors"
	"github.com/AdguardTeam/golibs/timeutil"
	"github.com/AdguardTeam/golibs/validate"
)

// QueryLogConfig is the on-disk query log configuration.
type QueryLogConfig struct {
	// DirPath is the custom directory for logs.  If it's empty the default
	// directory will be used.
	DirPath string `yaml:"dir_path"`

	// Ignored is the list of host names, which should not be written to log.
	// "." is considered to be the root domain.
	Ignored []string `yaml:"ignored"`

	// Interval is the interval for query log's files rotation.
	Interval timeutil.Duration `yaml:"interval"`

	// MemSize is the number of entries kept in memory before they are flushed
	// to disk.
	MemSize uint `yaml:"size_memory"`

	// Enabled defines if the query log is enabled.
	Enabled bool `yaml:"enabled"`

	// FileEnabled defines, if the query log is written to the file.
	FileEnabled bool `yaml:"file_enabled"`

	// IgnoredEnabled defines whether hosts from the ignored list should be
	// ignored.
	IgnoredEnabled bool `yaml:"ignored_enabled"`

	// MySQL contains the MySQL database configuration for query logging.
	MySQL QueryLogMySQLConfig `yaml:"mysql"`
}

// QueryLogMySQLConfig contains MySQL database configuration for query logging.
type QueryLogMySQLConfig struct {
	// DSN is the MySQL data source name (connection string).
	// Example: "user:password@tcp(localhost:3306)/adguard"
	DSN string `yaml:"dsn"`

	// Enabled defines if MySQL query logging is enabled.
	Enabled bool `yaml:"enabled"`
}

// type check
var _ validate.Interface = (*QueryLogConfig)(nil)

// Validate implements the [validate.Interface] interface for *QueryLogConfig.
func (c *QueryLogConfig) Validate() (err error) {
	if c == nil {
		return errors.ErrNoValue
	}

	// TODO(d.kolyshev):  Add more validations.

	return nil
}
