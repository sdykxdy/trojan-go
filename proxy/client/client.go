package client

import (
	"context"

	"github.com/sdykxdy/trojan-go/config"
	"github.com/sdykxdy/trojan-go/proxy"
	"github.com/sdykxdy/trojan-go/tunnel/adapter"
	"github.com/sdykxdy/trojan-go/tunnel/http"
	"github.com/sdykxdy/trojan-go/tunnel/mux"
	"github.com/sdykxdy/trojan-go/tunnel/router"
	"github.com/sdykxdy/trojan-go/tunnel/shadowsocks"
	"github.com/sdykxdy/trojan-go/tunnel/simplesocks"
	"github.com/sdykxdy/trojan-go/tunnel/socks"
	"github.com/sdykxdy/trojan-go/tunnel/tls"
	"github.com/sdykxdy/trojan-go/tunnel/transport"
	"github.com/sdykxdy/trojan-go/tunnel/trojan"
	"github.com/sdykxdy/trojan-go/tunnel/websocket"
)

const Name = "CLIENT"

// GenerateClientTree generate general outbound protocol stack
func GenerateClientTree(transportPlugin bool, muxEnabled bool, wsEnabled bool, ssEnabled bool, routerEnabled bool) []string {
	clientStack := []string{transport.Name}
	if !transportPlugin {
		clientStack = append(clientStack, tls.Name)
	}
	if wsEnabled {
		clientStack = append(clientStack, websocket.Name)
	}
	if ssEnabled {
		clientStack = append(clientStack, shadowsocks.Name)
	}
	clientStack = append(clientStack, trojan.Name)
	if muxEnabled {
		clientStack = append(clientStack, []string{mux.Name, simplesocks.Name}...)
	}
	if routerEnabled {
		clientStack = append(clientStack, router.Name)
	}
	return clientStack
}

func init() {
	proxy.RegisterProxyCreator(Name, func(ctx context.Context) (*proxy.Proxy, error) {
		cfg := config.FromContext(ctx, Name).(*Config)
		adapterServer, err := adapter.NewServer(ctx, nil)
		if err != nil {
			return nil, err
		}
		ctx, cancel := context.WithCancel(ctx)

		root := &proxy.Node{
			Name:       adapter.Name,
			Next:       make(map[string]*proxy.Node),
			IsEndpoint: false,
			Context:    ctx,
			Server:     adapterServer,
		}

		root.BuildNext(http.Name).IsEndpoint = true
		root.BuildNext(socks.Name).IsEndpoint = true

		clientStack := GenerateClientTree(cfg.TransportPlugin.Enabled, cfg.Mux.Enabled, cfg.Websocket.Enabled, cfg.Shadowsocks.Enabled, cfg.Router.Enabled)
		c, err := proxy.CreateClientStack(ctx, clientStack)
		if err != nil {
			cancel()
			return nil, err
		}
		s := proxy.FindAllEndpoints(root)
		return proxy.NewProxy(ctx, cancel, s, c), nil
	})
}
