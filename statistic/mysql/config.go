package mysql

import (
	"github.com/sdykxdy/trojan-go/config"
)

type MySQLConfig struct {
	Enabled    bool   `json:"enabled" yaml:"enabled"`
	DriverName string `json:"driver_name" yaml:"driver-name"`
	DataSource string `json:"data_source" yaml:"data-source"`
	CheckRate  int    `json:"check_rate" yaml:"check-rate"`
}

type Config struct {
	MySQL MySQLConfig `json:"mysql" yaml:"mysql"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{
			MySQL: MySQLConfig{
				CheckRate: 30,
			},
		}
	})
}
