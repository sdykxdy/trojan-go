//go:build custom || full
// +build custom full

package build

import (
	_ "github.com/sdykxdy/trojan-go/proxy/custom"
	_ "github.com/sdykxdy/trojan-go/tunnel/adapter"
	_ "github.com/sdykxdy/trojan-go/tunnel/dokodemo"
	_ "github.com/sdykxdy/trojan-go/tunnel/freedom"
	_ "github.com/sdykxdy/trojan-go/tunnel/http"
	_ "github.com/sdykxdy/trojan-go/tunnel/mux"
	_ "github.com/sdykxdy/trojan-go/tunnel/router"
	_ "github.com/sdykxdy/trojan-go/tunnel/shadowsocks"
	_ "github.com/sdykxdy/trojan-go/tunnel/simplesocks"
	_ "github.com/sdykxdy/trojan-go/tunnel/socks"
	_ "github.com/sdykxdy/trojan-go/tunnel/tls"
	_ "github.com/sdykxdy/trojan-go/tunnel/tproxy"
	_ "github.com/sdykxdy/trojan-go/tunnel/transport"
	_ "github.com/sdykxdy/trojan-go/tunnel/trojan"
	_ "github.com/sdykxdy/trojan-go/tunnel/websocket"
)
