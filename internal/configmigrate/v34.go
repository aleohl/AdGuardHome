package configmigrate

import "context"

// migrateTo34 performs the following changes:
//
//	# BEFORE:
//	'statistics':
//	  # …
//
//	# AFTER:
//	'statistics':
//	  # …
//	'notifications':
//	  'pushover':
//	    'enabled': false
//	    'app_token': ''
//	    'user_key': ''
//	    'rate_limit_per_5min': 1
//	    'global_rate_limit_per_min': 1
//	    'priority': 0
//	    'sound': ''
func (m Migrator) migrateTo34(_ context.Context, diskConf yobj) (err error) {
	diskConf["schema_version"] = 34

	// Add notifications section with Pushover defaults.
	diskConf["notifications"] = yobj{
		"pushover": yobj{
			"enabled":                   false,
			"app_token":                 "",
			"user_key":                  "",
			"rate_limit_per_5min":       1,
			"global_rate_limit_per_min": 1,
			"priority":                  0,
			"sound":                     "",
		},
	}

	return nil
}
