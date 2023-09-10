package vmess

import (
	"context"
	"fmt"
	"github.com/faireal/trojan-go/api/service"
	"github.com/faireal/trojan-go/common"
	"github.com/faireal/trojan-go/config"
	_ "github.com/faireal/trojan-go/log/golog"
	"github.com/faireal/trojan-go/statistic/memory"
	"github.com/faireal/trojan-go/test/util"
	"github.com/faireal/trojan-go/tunnel"
	"github.com/faireal/trojan-go/tunnel/freedom"
	"github.com/faireal/trojan-go/tunnel/transport"
	"testing"
	"time"
)

func TestVmessServer(t *testing.T) {
	port := 1234
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	serverConfig := &Config{
		RemoteHost: "127.0.0.1",
		RemotePort: util.EchoPort,
		UUID:       "a684455c-b14f-11ea-bf0d-42010aaa0003",
		Security:   "none",
		AlterID:    1,
		API:        APIConfig{Enabled: true},
	}
	// API
	APIconfig := &service.Config{service.APIConfig{
		Enabled: true,
		APIHost: "",
		APIPort: 20001,
	}}
	// mem
	menConfig := &memory.Config{
		Passwords: nil,
	}
	ctx = config.WithConfig(ctx, Name, serverConfig)
	ctx = config.WithConfig(ctx, service.Name, APIconfig)
	ctx = config.WithConfig(ctx, memory.Name, menConfig)
	s, err := NewServer(ctx, tcpServer)
	common.Must(err)
	conn2, err := s.AcceptConn(nil)
	common.Must(err)
	buf := make([]byte, 8)
	conn2.Read(buf[:])
	fmt.Println(string(buf))
	time.Sleep(5 * time.Second)
	conn2.Close()
	cancel()

}

func TestVmessClient(t *testing.T) {
	port := 1234
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	clientConfig := &Config{
		UUID:     "a684455c-b14f-11ea-bf0d-42010aaa0003",
		Security: "none",
		AlterID:  4,
	}
	clientCtx := config.WithConfig(ctx, Name, clientConfig)
	c, err := NewClient(clientCtx, tcpClient)
	common.Must(err)
	conn1, err := c.DialConn(&tunnel.Address{
		DomainName:  "example.com",
		AddressType: tunnel.DomainName,
	}, nil)
	common.Must(err)
	common.Must2(conn1.Write([]byte("87654321")))
	time.Sleep(5 * time.Second)
	conn1.Close()

	cancel()
}

func TestVmess(t *testing.T) {
	port := common.PickPort("tcp", "127.0.0.1")
	transportConfig := &transport.Config{
		LocalHost:  "127.0.0.1",
		LocalPort:  port,
		RemoteHost: "127.0.0.1",
		RemotePort: port,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ctx = config.WithConfig(ctx, transport.Name, transportConfig)
	ctx = config.WithConfig(ctx, freedom.Name, &freedom.Config{})
	tcpClient, err := transport.NewClient(ctx, nil)
	common.Must(err)
	tcpServer, err := transport.NewServer(ctx, nil)
	common.Must(err)

	clientConfig := &Config{
		UUID:     "a684455c-b14f-11ea-bf0d-42010aaa0003",
		Security: "none",
		AlterID:  4,
	}
	serverConfig := &Config{
		RemoteHost: "127.0.0.1",
		RemotePort: util.EchoPort,
		UUID:       "a684455c-b14f-11ea-bf0d-42010aaa0003",
		Security:   "none",
		AlterID:    4,
	}

	clientCtx := config.WithConfig(ctx, Name, clientConfig)
	serverCtx := config.WithConfig(ctx, Name, serverConfig)
	c, err := NewClient(clientCtx, tcpClient)
	common.Must(err)
	s, err := NewServer(serverCtx, tcpServer)
	common.Must(err)
	conn1, err := c.DialConn(&tunnel.Address{
		DomainName:  "example.com",
		AddressType: tunnel.DomainName,
	}, nil)
	common.Must(err)
	common.Must2(conn1.Write([]byte("87654321")))
	conn2, err := s.AcceptConn(nil)
	common.Must(err)
	buf := make([]byte, 8)
	conn2.Read(buf[:])
	fmt.Println(string(buf))
	if !util.CheckConn(conn1, conn2) {
		t.Fail()
	}
	conn1.Close()
	conn2.Close()
	c.Close()
	s.Close()
	cancel()
}
