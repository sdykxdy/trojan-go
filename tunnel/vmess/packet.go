package vmess

import (
	"github.com/faireal/trojan-go/log"
	"github.com/faireal/trojan-go/tunnel"
	"net"
)

type PacketConn struct {
	tunnel.Conn
}

func (c *PacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	return c.ReadWithMetadata(payload)
}

func (c *PacketConn) WriteTo(payload []byte, addr net.Addr) (int, error) {
	address, err := tunnel.NewAddressFromAddr("udp", addr.String())
	if err != nil {
		return 0, err
	}
	m := &tunnel.Metadata{
		Address: address,
	}
	return c.WriteWithMetadata(payload, m)
}

func (c *PacketConn) WriteWithMetadata(payload []byte, metadata *tunnel.Metadata) (int, error) {
	n, err := c.Conn.Write(payload)
	log.Info("udp packet remote", c.RemoteAddr(), "metadata", metadata, "size", n)
	return n, err
}

func (c *PacketConn) ReadWithMetadata(payload []byte) (int, *tunnel.Metadata, error) {
	n, err := c.Conn.Read(payload)
	c.Metadata().Address.NetworkType = "udp"
	log.Info("udp packet from", c.RemoteAddr(), "metadata", c.Metadata(), "size", n)
	return n, c.Metadata(), err
}
