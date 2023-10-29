package vmess

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/sdykxdy/trojan-go/common/pool"
	"io"
	"sync"
)

type aeadWriter struct {
	io.Writer
	cipher.AEAD
	nonce       [32]byte
	count       uint16
	iv          []byte
	shakeParser *ShakeSizeParser
	writeLock   sync.Mutex
}

func newAEADWriter(w io.Writer, aead cipher.AEAD, iv []byte, shakeParser *ShakeSizeParser) *aeadWriter {
	return &aeadWriter{Writer: w, AEAD: aead, iv: iv, shakeParser: shakeParser}
}

func (w *aeadWriter) Write(b []byte) (n int, err error) {
	w.writeLock.Lock()
	buf := pool.Get(pool.RelayBufferSize)
	defer func() {
		w.writeLock.Unlock()
		pool.Put(buf)
	}()
	length := len(b)
	for {
		if length == 0 {
			break
		}
		if w.shakeParser != nil {
			paddingSize := int(w.shakeParser.NextPaddingLen())
			readLen := chunkSize - w.Overhead() - paddingSize
			if length < readLen {
				readLen = length
			}
			encryptedSize := (readLen + w.Overhead())
			totalSize := lenSize + encryptedSize + paddingSize

			eb := buf[:totalSize]

			w.shakeParser.Encode(uint16(encryptedSize+paddingSize), eb[:lenSize])
			encryptBuf := eb[lenSize : lenSize+encryptedSize]

			binary.BigEndian.PutUint16(w.nonce[:2], w.count)
			copy(w.nonce[2:], w.iv[2:12])
			// 注意 读写数据加密不一样 写的时候是真实数据，读的时候是真实数据+Overhead
			w.Seal(encryptBuf[:0], w.nonce[:w.NonceSize()], b[n:n+readLen], nil)
			w.count++

			if paddingSize > 0 {
				rand.Read(eb[lenSize+encryptedSize:])
			}
			_, err = w.Writer.Write(eb[:totalSize])
			if err != nil {
				break
			}
			n += readLen
			length -= readLen
		} else {
			readLen := chunkSize - w.Overhead()
			if length < readLen {
				readLen = length
			}
			payloadBuf := buf[lenSize : lenSize+chunkSize-w.Overhead()]
			copy(payloadBuf, b[n:n+readLen])

			binary.BigEndian.PutUint16(buf[:lenSize], uint16(readLen+w.Overhead()))
			binary.BigEndian.PutUint16(w.nonce[:2], w.count)
			copy(w.nonce[2:], w.iv[2:12])

			w.Seal(payloadBuf[:0], w.nonce[:w.NonceSize()], payloadBuf[:readLen], nil)
			w.count++

			_, err = w.Writer.Write(buf[:lenSize+readLen+w.Overhead()])
			if err != nil {
				break
			}
			n += readLen
			length -= readLen
		}

	}
	return
}

type aeadReader struct {
	io.Reader
	cipher.AEAD
	nonce       [32]byte
	buf         []byte
	offset      int
	iv          []byte
	sizeBuf     []byte
	count       uint16
	shakeParser *ShakeSizeParser
}

func newAEADReader(r io.Reader, aead cipher.AEAD, iv []byte, shakeParser *ShakeSizeParser) *aeadReader {
	return &aeadReader{Reader: r, AEAD: aead, iv: iv, sizeBuf: make([]byte, lenSize), shakeParser: shakeParser}
}

func (r *aeadReader) Read(b []byte) (int, error) {
	if r.buf != nil {
		n := copy(b, r.buf[r.offset:])
		r.offset += n
		if r.offset == len(r.buf) {
			pool.Put(r.buf)
			r.buf = nil
		}
		return n, nil
	}
	// size = readLen + Overhead()
	var size int = 0
	// 填充数据长度
	var paddingLen uint16 = 0
	// totalsize = size + paddingLen
	var totalsize uint16 = 0

	_, err := io.ReadFull(r.Reader, r.sizeBuf)
	if err != nil {
		return 0, err
	}
	if r.shakeParser != nil {
		paddingLen = r.shakeParser.NextPaddingLen()
		totalsize, err = r.shakeParser.Decode(r.sizeBuf)
		if err != nil {
			return 0, err
		}
		size = int(totalsize - paddingLen)
		if size == r.Overhead() {
			return 0, io.EOF
		}
	} else {
		size = int(binary.BigEndian.Uint16(r.sizeBuf))
	}

	if size > maxSize {
		return 0, errors.New("buffer is larger than standard")
	}
	// 把所有的数据读出来
	readdatelen := size + int(paddingLen)

	buf := pool.Get(readdatelen)
	_, err = io.ReadFull(r.Reader, buf[:readdatelen])
	if err != nil {
		pool.Put(buf)
		return 0, err
	}
	if r.shakeParser != nil {
		buf = buf[:size]
	}

	binary.BigEndian.PutUint16(r.nonce[:2], r.count)
	copy(r.nonce[2:], r.iv[2:12])

	// 注意 读写数据加密不一样 写的时候是真实数据，读的时候是真实数据+Overhead
	_, err = r.Open(buf[:0], r.nonce[:r.NonceSize()], buf[:size], nil)
	r.count++
	if err != nil {
		return 0, err
	}
	realLen := size - r.Overhead()
	n := copy(b, buf[:realLen])
	if len(b) >= realLen {
		pool.Put(buf)
		return n, nil
	}

	r.offset = n
	r.buf = buf[:realLen]
	return n, nil
}
