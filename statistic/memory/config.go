package memory

import (
	"github.com/sdykxdy/trojan-go/config"
)

type Config struct {
	Passwords []string `json:"password" yaml:"password"`
}

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return &Config{}
	})
}
