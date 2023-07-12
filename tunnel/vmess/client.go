package vmess

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
	"github.com/faireal/trojan-go/common"
	"github.com/faireal/trojan-go/config"
	"github.com/faireal/trojan-go/tunnel"
	"golang.org/x/crypto/chacha20poly1305"
	"hash/fnv"
	"io"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

const (
	TCP tunnel.Command = 1
	UDP tunnel.Command = 2
)

type OutboundConn struct {
	user *User
	net.Conn
	reader io.Reader
	writer io.Writer

	reqBodyIV   [16]byte
	reqBodyKey  [16]byte
	reqRespV    byte
	respBodyIV  [16]byte
	respBodyKey [16]byte

	security byte
	opt      byte

	metadata *tunnel.Metadata
}

func (vc *OutboundConn) Write(b []byte) (int, error) {
	if vc.writer == nil {
		vc.writer = vc.Conn
		if vc.opt&OptChunkStream == OptChunkStream {
			switch vc.security {
			case SecurityNone:
				vc.writer = ChunkedWriter(vc.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(vc.reqBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				vc.writer = AEADWriter(vc.Conn, aead, vc.reqBodyIV[:])

			case SecurityChacha20Poly1305:
				key := GetBuffer(32)
				t := md5.Sum(vc.reqBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				vc.writer = AEADWriter(vc.Conn, aead, vc.reqBodyIV[:])
				PutBuffer(key)
			}
		}
	}
	return vc.writer.Write(b)
}

func (vc *OutboundConn) Read(b []byte) (int, error) {
	if vc.reader == nil {
		err := vc.DecodeRespHeader()
		if err != nil {
			return 0, err
		}

		vc.reader = vc.Conn
		if vc.opt&OptChunkStream == OptChunkStream {
			switch vc.security {
			case SecurityNone:
				vc.reader = ChunkedReader(vc.Conn)

			case SecurityAES128GCM:
				block, _ := aes.NewCipher(vc.respBodyKey[:])
				aead, _ := cipher.NewGCM(block)
				vc.reader = AEADReader(vc.Conn, aead, vc.respBodyIV[:])

			case SecurityChacha20Poly1305:
				key := GetBuffer(32)
				t := md5.Sum(vc.respBodyKey[:])
				copy(key, t[:])
				t = md5.Sum(key[:16])
				copy(key[16:], t[:])
				aead, _ := chacha20poly1305.New(key)
				vc.reader = AEADReader(vc.Conn, aead, vc.respBodyIV[:])
				PutBuffer(key)
			}
		}
	}
	return vc.reader.Read(b)
}

func (vc *OutboundConn) Auth() error {
	ts := GetBuffer(8)
	defer PutBuffer(ts)
	binary.BigEndian.PutUint64(ts, uint64(time.Now().UTC().Unix()))
	h := hmac.New(md5.New, vc.user.UUID[:])
	h.Write(ts)

	_, err := vc.Conn.Write(h.Sum(nil))
	return err

}

func (vc *OutboundConn) DecodeRespHeader() error {
	block, err := aes.NewCipher(vc.respBodyKey[:])
	if err != nil {
		return err
	}

	stream := cipher.NewCFBDecrypter(block, vc.respBodyIV[:])

	b := GetBuffer(4)
	defer PutBuffer(b)

	_, err = io.ReadFull(vc.Conn, b)
	if err != nil {
		return err
	}

	stream.XORKeyStream(b, b)

	if b[0] != vc.reqRespV {
		return errors.New("unexpected response header")
	}

	if b[2] != 0 {
		// dataLen := int32(buf[3])
		return errors.New("dynamic port is not supported now")
	}

	return nil
}

func (vc *OutboundConn) Request() error {
	buf := GetWriteBuffer()
	defer PutWriteBuffer(buf)
	// Request
	buf.WriteByte(1)            // Ver
	buf.Write(vc.reqBodyIV[:])  // IV
	buf.Write(vc.reqBodyKey[:]) // Key
	buf.WriteByte(vc.reqRespV)  // V
	buf.WriteByte(vc.opt)       // Opt

	// pLen and Sec
	paddingLen := rand.Intn(16)
	pSec := byte(paddingLen<<4) | vc.security // P(4bit) and Sec(4bit)
	buf.WriteByte(pSec)

	buf.WriteByte(0)      // reserved
	buf.WriteByte(CmdTCP) // cmd

	// target
	err := binary.Write(buf, binary.BigEndian, uint16(vc.metadata.Port)) // port
	if err != nil {
		return err
	}
	switch vc.metadata.AddressType {
	case tunnel.DomainName:
		buf.WriteByte(byte(2))
		buf.Write([]byte{byte(len(vc.metadata.DomainName))})
		buf.Write([]byte(vc.metadata.DomainName))
	case tunnel.IPv4:
		buf.WriteByte(byte(1))
		buf.Write(vc.metadata.IP.To4())
	case tunnel.IPv6:
		buf.WriteByte(byte(3))
		buf.Write(vc.metadata.IP.To4())
	default:
		return common.NewError("invalid ATYP " + strconv.FormatInt(int64(vc.metadata.AddressType), 10))
	}
	//buf.WriteByte(c.atyp) // atyp
	//buf.Write(c.addr)     // addr

	// padding
	if paddingLen > 0 {
		padding := GetBuffer(paddingLen)
		rand.Read(padding)
		buf.Write(padding)
		PutBuffer(padding)
	}

	// F
	fnv1a := fnv.New32a()
	_, err = fnv1a.Write(buf.Bytes())
	if err != nil {
		return err
	}
	buf.Write(fnv1a.Sum(nil))

	// log.Printf("Request Send %v", buf.Bytes())

	block, err := aes.NewCipher(vc.user.CmdKey[:])
	if err != nil {
		return err
	}

	stream := cipher.NewCFBEncrypter(block, TimestampHash(time.Now().UTC().Unix()))
	stream.XORKeyStream(buf.Bytes(), buf.Bytes())

	_, err = vc.Conn.Write(buf.Bytes())

	return err
}

func (c *OutboundConn) Metadata() *tunnel.Metadata {
	return c.metadata
}

type Client struct {
	underlay tunnel.Client
	ctx      context.Context
	cancel   context.CancelFunc
	users    []*User
	opt      byte
	security byte
}

func (c *Client) DialConn(addr *tunnel.Address, t tunnel.Tunnel) (tunnel.Conn, error) {
	conn, err := c.underlay.DialConn(addr, &Tunnel{})
	if err != nil {
		return nil, err
	}
	newConn := &OutboundConn{Conn: conn, metadata: &tunnel.Metadata{
		Command: TCP,
		Address: addr,
	}}
	err = c.handshake(newConn)
	if err != nil {
		return nil, err
	}
	return newConn, nil

}

func (c *Client) DialPacket(t tunnel.Tunnel) (tunnel.PacketConn, error) {
	//TODO implement me
	panic("implement me")
}

func (c *Client) handshake(conn *OutboundConn) error {
	r := rand.Intn(len(c.users))
	conn.user = c.users[r]
	randBytes := GetBuffer(32)
	rand.Read(randBytes)
	copy(conn.reqBodyIV[:], randBytes[:16])
	copy(conn.reqBodyKey[:], randBytes[16:32])
	PutBuffer(randBytes)
	conn.reqRespV = byte(rand.Intn(1 << 8))
	conn.respBodyIV = md5.Sum(conn.reqBodyIV[:])
	conn.respBodyKey = md5.Sum(conn.reqBodyKey[:])

	// Auth
	err := conn.Auth()
	if err != nil {
		return err
	}

	// Request
	err = conn.Request()
	if err != nil {
		return err
	}

	return nil
}

func (c *Client) Close() error {
	c.cancel()
	return c.underlay.Close()
}

func NewClient(ctx context.Context, client tunnel.Client) (*Client, error) {
	cfg := config.FromContext(ctx, Name).(*Config)
	ctx, cancel := context.WithCancel(ctx)
	c := &Client{underlay: client, ctx: ctx, cancel: cancel}
	uuid, err := StrToUUID(cfg.UUID)
	if err != nil {
		cancel()
		return nil, err
	}
	user := NewUser(uuid)
	c.users = append(c.users, user)
	c.users = append(c.users, user.GenAlterIDUsers(cfg.AlterID)...)
	c.opt = OptChunkStream
	security := strings.ToLower(cfg.Security)
	switch security {
	case "aes-128-gcm":
		c.security = SecurityAES128GCM
	case "chacha20-poly1305":
		c.security = SecurityChacha20Poly1305
	case "none":
		c.security = SecurityNone
	case "":
		// NOTE: use basic format when no method specified
		c.opt = OptBasicFormat
		c.security = SecurityNone
	default:
		return nil, errors.New("unknown security type: " + security)
	}
	rand.Seed(time.Now().UnixNano())
	return c, nil
}
