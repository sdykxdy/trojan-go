package shadowsocks

import (
	"context"
	"github.com/sdykxdy/trojan-go/common"
	"github.com/sdykxdy/trojan-go/config"
	"github.com/sdykxdy/trojan-go/log"
	"github.com/sdykxdy/trojan-go/redirector"
	"github.com/sdykxdy/trojan-go/tunnel"
	"github.com/shadowsocks/go-shadowsocks2/core"
	"net"
)

type Server struct {
	core.Cipher
	*redirector.Redirector
	underlay  tunnel.Server
	redirAddr net.Addr
	connChan  chan tunnel.Conn
	ctx       context.Context
	cancel    context.CancelFunc
}

func (s *Server) AcceptConn(overlay tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case t := <-s.connChan:
		return t, nil
	case <-s.ctx.Done():
		return nil, common.NewError("shadowsocks client closed")
	}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("shadowsocks failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(1024)
			defer rewindConn.StopBuffering()
			log.Info("shadowsocks connection from", conn.RemoteAddr())
			// try to read something from this connection
			buf := [1024]byte{}
			testConn := s.Cipher.StreamConn(rewindConn)
			if _, err := testConn.Read(buf[:]); err != nil {
				// we are under attack
				log.Error(common.NewError("shadowsocks failed to decrypt").Base(err))
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				s.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}
			rewindConn.Rewind()
			rewindConn.StopBuffering()
			s.connChan <- &Conn{
				aeadConn: s.Cipher.StreamConn(rewindConn),
				Conn:     conn,
			}
		}(conn)
	}
}

func (s *Server) AcceptPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	panic("not supported")
}

func (s *Server) Close() error {
	s.cancel()
	return s.underlay.Close()
}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	cipher, err := core.PickCipher(cfg.Shadowsocks.Method, nil, cfg.Shadowsocks.Password)
	if err != nil {
		return nil, common.NewError("invalid shadowsocks cipher").Base(err)
	}
	if cfg.RemoteHost == "" {
		return nil, common.NewError("invalid shadowsocks redirection address")
	}
	if cfg.RemotePort == 0 {
		return nil, common.NewError("invalid shadowsocks redirection port")
	}
	log.Debug("shadowsocks client created")
	s := &Server{
		underlay:   underlay,
		Cipher:     cipher,
		Redirector: redirector.NewRedirector(ctx),
		redirAddr:  tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort),
		ctx:        ctx,
		cancel:     cancel,
		connChan:   make(chan tunnel.Conn, 32),
	}
	go s.acceptLoop()
	return s, nil
}
