package server

import (
	"github.com/faireal/trojan-go/config"
	"github.com/faireal/trojan-go/proxy/client"
)

func init() {
	config.RegisterConfigCreator(Name, func() interface{} {
		return new(client.Config)
	})
}
