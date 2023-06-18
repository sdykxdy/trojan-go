//go:build custom || full
// +build custom full

package build

import (
	_ "github.com/faireal/trojan-go/proxy/custom"
	_ "github.com/faireal/trojan-go/tunnel/adapter"
	_ "github.com/faireal/trojan-go/tunnel/dokodemo"
	_ "github.com/faireal/trojan-go/tunnel/freedom"
	_ "github.com/faireal/trojan-go/tunnel/http"
	_ "github.com/faireal/trojan-go/tunnel/mux"
	_ "github.com/faireal/trojan-go/tunnel/router"
	_ "github.com/faireal/trojan-go/tunnel/shadowsocks"
	_ "github.com/faireal/trojan-go/tunnel/simplesocks"
	_ "github.com/faireal/trojan-go/tunnel/socks"
	_ "github.com/faireal/trojan-go/tunnel/tls"
	_ "github.com/faireal/trojan-go/tunnel/tproxy"
	_ "github.com/faireal/trojan-go/tunnel/transport"
	_ "github.com/faireal/trojan-go/tunnel/trojan"
	_ "github.com/faireal/trojan-go/tunnel/websocket"
)
