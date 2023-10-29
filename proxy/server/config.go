package server

import (
	"github.com/sdykxdy/trojan-go/config"
	"github.com/sdykxdy/trojan-go/proxy/client"
)

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(client.Config)
	})
}
