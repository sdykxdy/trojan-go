package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/faireal/trojan-go/api/service"
	"github.com/faireal/trojan-go/common"
	"github.com/faireal/trojan-go/config"
	"github.com/faireal/trojan-go/log"
	"github.com/faireal/trojan-go/redirector"
	"github.com/faireal/trojan-go/statistic"
	"github.com/faireal/trojan-go/statistic/memory"
	"github.com/faireal/trojan-go/tunnel"
	"golang.org/x/crypto/chacha20poly1305"
	"hash/fnv"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

const (
	updateInterval   = 30 * time.Second
	cacheDurationSec = 120
	sessionTimeOut   = 3 * time.Minute
)

// InboundConn is a vmess inbound connection
type InboundConn struct {
	// WARNING: do not change the order of these fields.
	// 64-bit fields that use `sync/atomic` package functions
	// must be 64-bit aligned on 32-bit systems.
	// Reference: https://github.com/golang/go/issues/599
	// Solution: https://github.com/golang/go/issues/11891#issuecomment-433623786
	sent uint64
	recv uint64

	net.Conn
	auth     statistic.Authenticator
	user     statistic.User
	hash     string
	metadata *tunnel.Metadata
	ip       string

	// header
	dataReader io.Reader
	dataWriter io.Writer

	opt      byte
	security byte

	reqBodyIV   [16]byte
	reqBodyKey  [16]byte
	reqRespV    byte
	respBodyIV  [16]byte
	respBodyKey [16]byte
}

type UserAtTime struct {
	user    statistic.User
	timeInc int64
	tainted bool // 是否被重放攻击污染
}

type SessionId struct {
	user  [16]byte
	key   [16]byte
	nonce [16]byte
}

func (c *InboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

func (c *InboundConn) Write(p []byte) (int, error) {
	if c.dataWriter == nil {
		// 编码响应头
		// 应答头部数据使用 AES-128-CFB 加密，IV 为 MD5(数据加密 IV)，Key 为 MD5(数据加密 Key)
		buf := GetWriteBuffer()
		defer PutWriteBuffer(buf)

		buf.WriteByte(c.reqRespV) // 响应认证 V
		buf.WriteByte(c.opt)      // 选项 Opt
		buf.Write([]byte{0, 0})   // 指令 Cmd 和 长度 M, 不支持动态端口指令

		c.respBodyKey = md5.Sum(c.reqBodyKey[:])
		c.respBodyIV = md5.Sum(c.reqBodyIV[:])

		block, err := aes.NewCipher(c.respBodyKey[:])
		if err != nil {
			return 0, err
		}

		stream := cipher.NewCFBEncrypter(block, c.respBodyIV[:])
		stream.XORKeyStream(buf.Bytes(), buf.Bytes())
		_, err = c.Conn.Write(buf.Bytes())
		if err != nil {
			return 0, err
		}

		// 编码内容
		c.dataWriter = c.Conn
		if c.opt&OptChunkStream == OptChunkStream {
			switch c.security {
			case SecurityNone:
				c.dataWriter = ChunkedWriter(c.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(c.reqBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])

			case SecurityChacha20Poly1305:
				key := GetBuffer(32)
				t := md5.Sum(c.reqBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				c.dataWriter = AEADWriter(c.Conn, aead, c.reqBodyIV[:])
				PutBuffer(key)
			}
		}
	}
	n, err := c.dataWriter.Write(p)
	atomic.AddUint64(&c.sent, uint64(n))
	c.user.AddTraffic(n, 0)
	return n, err
}

func (c *InboundConn) Read(p []byte) (n int, err error) {
	if c.dataReader == nil {
		// 解码数据部分
		c.dataReader = c.Conn
		if c.opt&OptChunkStream == OptChunkStream {
			switch c.security {
			case SecurityNone:
				c.dataReader = ChunkedReader(c.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(c.reqBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				c.dataReader = AEADReader(c.Conn, aead, c.reqBodyIV[:])

			case SecurityChacha20Poly1305:
				key := GetBuffer(32)
				t := md5.Sum(c.reqBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				c.dataReader = AEADReader(c.Conn, aead, c.reqBodyIV[:])
				PutBuffer(key)
			}
		}
	}
	n, err = c.dataReader.Read(p)
	atomic.AddUint64(&c.recv, uint64(n))
	c.user.AddTraffic(0, n)
	return n, err
}

func (c *InboundConn) Close() error {
	log.Info("user", c.hash, "from", c.Conn.RemoteAddr(), "tunneling to", c.metadata.Address, "closed",
		"sent:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.sent)), "recv:", common.HumanFriendlyTraffic(atomic.LoadUint64(&c.recv)))
	c.user.DelIP(c.ip)
	return c.Conn.Close()
}

type Server struct {
	auth      statistic.Authenticator
	redir     *redirector.Redirector
	redirAddr *tunnel.Address
	underlay  tunnel.Server
	connChan  chan tunnel.Conn
	ctx       context.Context
	cancel    context.CancelFunc

	// userHashes用于校验VMess请求的认证信息部分
	// sessionHistory保存一段时间内的请求用来检测重放攻击
	baseTime       int64
	userHashes     map[[16]byte]*UserAtTime
	sessionHistory map[SessionId]time.Time

	// 定时刷新userHashes和sessionHistory
	mux4Hashes, mux4Sessions sync.RWMutex
	ticker                   *time.Ticker
	quit                     chan struct{}
}

func (s *Server) acceptLoop() {
	for {
		conn, err := s.underlay.AcceptConn(&Tunnel{})
		if err != nil { // Closing
			log.Error(common.NewError("vmess failed to accept conn").Base(err))
			select {
			case <-s.ctx.Done():
				return
			default:
			}
			continue
		}
		go func(conn tunnel.Conn) {
			rewindConn := common.NewRewindConn(conn)
			rewindConn.SetBufferSize(4086)
			defer rewindConn.StopBuffering()
			inboundConn := &InboundConn{
				Conn: rewindConn,
			}
			if err := s.handshake(inboundConn); err != nil {
				rewindConn.Rewind()
				rewindConn.StopBuffering()
				log.Warn(common.NewError("connection with invalid vmess header from " + rewindConn.RemoteAddr().String()).Base(err))
				s.redir.Redirect(&redirector.Redirection{
					RedirectTo:  s.redirAddr,
					InboundConn: rewindConn,
				})
				return
			}
			rewindConn.StopBuffering()
			s.connChan <- inboundConn
			log.Debug("normal vmess connection")
		}(conn)
	}

}

func (s *Server) AcceptConn(t tunnel.Tunnel) (tunnel.Conn, error) {
	select {
	case c := <-s.connChan:
		return c, nil
	case <-s.ctx.Done():
		return nil, common.NewError("vmess client closed")
	}
}

func (s *Server) AcceptPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	//TODO implement me
	panic("implement me")
}

func (s *Server) Close() error {
	close(s.quit)
	return s.underlay.Close()
}

func (s *Server) handshake(c *InboundConn) error {

	// Set handshake timeout 4 seconds
	//if err := c.SetReadDeadline(time.Now().Add(time.Second * 20)); err != nil {
	//	return err
	//}
	//defer c.SetReadDeadline(time.Time{})
	var auth [16]byte
	_, err := io.ReadFull(c.Conn, auth[:])
	if err != nil {
		return err
	}
	var timestamp int64
	s.mux4Hashes.RLock()
	uat, found := s.userHashes[auth]
	if !found || uat.tainted {
		s.mux4Hashes.RUnlock()
		return errors.New("invalid user or tainted")
	}
	c.user = uat.user
	timestamp = uat.timeInc + s.baseTime
	s.mux4Hashes.RUnlock()
	//
	// 解开指令部分，该部分使用了AES-128-CFB加密
	//
	fullReq := GetWriteBuffer()
	defer PutWriteBuffer(fullReq)
	// 创建一个AES  加密器
	cmdkey := c.user.CmdKey()
	block, err := aes.NewCipher(cmdkey[:])
	if err != nil {
		return err
	}
	stream := cipher.NewCFBDecrypter(block, TimestampHash(timestamp))
	// 41{1 + 16 + 16 + 1 + 1 + 1 + 1 + 1 + 2 + 1} + 1 + MAX{255} + MAX{15} + 4 = 362
	req := GetBuffer(41)
	defer PutBuffer(req)
	_, err = io.ReadFull(c.Conn, req)
	if err != nil {
		return err
	}
	stream.XORKeyStream(req, req)
	fullReq.Write(req)

	copy(c.reqBodyIV[:], req[1:17])   // 16 bytes, 数据加密 IV
	copy(c.reqBodyKey[:], req[17:33]) // 16 bytes, 数据加密 Key

	var sid SessionId
	uuid := c.user.UUID()
	copy(sid.user[:], uuid[:])
	sid.key = c.reqBodyKey
	sid.nonce = c.reqBodyIV
	s.mux4Sessions.Lock()
	now := time.Now().UTC()
	if expire, found := s.sessionHistory[sid]; found && expire.After(now) {
		s.mux4Sessions.Unlock()
		return errors.New("duplicated session id")
	}
	s.sessionHistory[sid] = now.Add(sessionTimeOut)
	s.mux4Sessions.Unlock()

	c.reqRespV = req[33]           // 1 byte, 直接用于响应的认证
	c.opt = req[34]                // 1 byte
	padingLen := int(req[35] >> 4) // 4 bits, 余量 P
	c.security = req[35] & 0x0F    // 4 bits, 加密方式 Sec
	cmd := req[37]                 // 1 byte, 指令 Cmd
	if cmd != CmdTCP {
		return fmt.Errorf("unsuppoted command %v", cmd)
	}

	// 解析地址, 从41位开始读
	addr := &tunnel.Address{}
	addr.Port = int(binary.BigEndian.Uint16(req[38:40]))
	l := 0
	switch req[40] {
	case AtypIP4:
		l = net.IPv4len
		addr.IP = make(net.IP, net.IPv4len)
		addr.AddressType = tunnel.IPv4
	case AtypDomain:
		// 解码域名的长度
		reqLength := GetBuffer(1)
		defer PutBuffer(reqLength)
		_, err = io.ReadFull(c.Conn, reqLength)
		if err != nil {
			return err
		}
		stream.XORKeyStream(reqLength, reqLength)
		fullReq.Write(reqLength)
		l = int(reqLength[0])
		addr.AddressType = tunnel.DomainName
	case AtypIP6:
		l = net.IPv6len
		addr.IP = make(net.IP, net.IPv6len)
		addr.AddressType = tunnel.IPv6
	default:
		return fmt.Errorf("unknown address type %v", req[40])
	}

	// 解码剩余部分
	reqRemaining := GetBuffer(l + padingLen + 4)
	defer PutBuffer(reqRemaining)
	_, err = io.ReadFull(c.Conn, reqRemaining)
	if err != nil {
		return err
	}
	stream.XORKeyStream(reqRemaining, reqRemaining)
	fullReq.Write(reqRemaining)

	if addr.IP != nil {
		copy(addr.IP, reqRemaining[:l])
	} else {
		addr.DomainName = string(reqRemaining[:l])
	}

	full := fullReq.Bytes()
	// log.Printf("Request Recv %v", full)

	// 跳过余量读取四个字节的校验F
	fnv1a := fnv.New32a()
	_, err = fnv1a.Write(full[:len(full)-4])
	if err != nil {
		return err
	}
	actualHash := fnv1a.Sum32()
	expectedHash := binary.BigEndian.Uint32(reqRemaining[len(reqRemaining)-4:])
	if actualHash != expectedHash {
		return errors.New("invalid req")
	}
	c.metadata = &tunnel.Metadata{Command: tunnel.Command(cmd), Address: addr}

	// ip 限制
	ip, _, err := net.SplitHostPort(c.Conn.RemoteAddr().String())
	if err != nil {
		return common.NewError("failed to parse host:" + c.Conn.RemoteAddr().String()).Base(err)
	}

	c.ip = ip
	ok := c.user.AddIP(ip)
	if !ok {
		return common.NewError("ip limit reached")
	}
	return nil

}

func NewServer(ctx context.Context, underlay tunnel.Server) (*Server, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	redirAddr := tunnel.NewAddressFromHostPort("tcp", cfg.RemoteHost, cfg.RemotePort)
	auth, err := statistic.NewAuthenticator(ctx, memory.Name)
	if err != nil {
		return nil, common.NewError("vmess failed to create authenticator")
	}
	s := &Server{
		underlay:  underlay,
		auth:      auth,
		ctx:       ctx,
		redirAddr: redirAddr,
		cancel:    cancel,
		connChan:  make(chan tunnel.Conn, 32),
		redir:     redirector.NewRedirector(ctx),
	}
	if cfg.API.Enabled {
		go service.RunServerAPI(ctx, auth)
	}
	err = s.auth.AddUser(cfg.UUID)
	if err != nil {
		return nil, err
	}
	s.baseTime = time.Now().UTC().Unix() - cacheDurationSec*2
	s.userHashes = make(map[[16]byte]*UserAtTime, 1024)
	s.sessionHistory = make(map[SessionId]time.Time, 128)
	s.ticker = time.NewTicker(updateInterval)
	s.quit = make(chan struct{})
	go s.refreloop()
	go s.acceptLoop()
	return s, nil

}

func (s *Server) refreloop() {
	s.refresh()
	for {
		select {
		case <-s.ticker.C:
			s.refresh()
		case <-s.quit:
			s.ticker.Stop()
			return
		}
	}
}

func (s *Server) refresh() {
	s.mux4Hashes.Lock()
	now := time.Now().UTC()
	nowSec := now.Unix()
	genBeginSec := nowSec - cacheDurationSec
	genEndSec := nowSec + cacheDurationSec
	var hashValue [16]byte
	users := s.auth.ListUsers()
	for _, user := range users {
		uuid := user.UUID()
		hasher := hmac.New(md5.New, uuid[:])
		for ts := genBeginSec; ts <= genEndSec; ts++ {
			var b [8]byte
			binary.BigEndian.PutUint64(b[:], uint64(ts))
			hasher.Write(b[:])
			hasher.Sum(hashValue[:0])
			hasher.Reset()

			s.userHashes[hashValue] = &UserAtTime{
				user:    user,
				timeInc: ts - s.baseTime,
				tainted: false,
			}
		}
	}
	if genBeginSec > s.baseTime {
		for k, v := range s.userHashes {
			if v.timeInc+s.baseTime < genBeginSec {
				delete(s.userHashes, k)
			}
		}
	}
	s.mux4Hashes.Unlock()

	s.mux4Sessions.Lock()
	for session, expire := range s.sessionHistory {
		if expire.Before(now) {
			delete(s.sessionHistory, session)
		}
	}
	s.mux4Sessions.Unlock()
}

func (s *Server) AddUser(uuid string) error {
	return nil
}

func (s *Server) DelUser(uuid string) error {
	return nil
}
