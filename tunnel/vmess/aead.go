package vmess

import (
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"
	"sync"
)

const (
	RelayBufferSize = 20 * 1024
)

type aeadWriter struct {
	io.Writer
	cipher.AEAD
	nonce []byte
	count uint16
	iv    []byte

	writeLock sync.Mutex
}

// AEADWriter returns a aead writer
func AEADWriter(w io.Writer, aead cipher.AEAD, iv []byte) io.Writer {
	return &aeadWriter{Writer: w, AEAD: aead, iv: iv}
}

func (w *aeadWriter) Write(b []byte) (n int, err error) {
	w.writeLock.Lock()
	buf := GetBuffer(RelayBufferSize)
	defer func() {
		w.writeLock.Unlock()
		PutBuffer(buf)
	}()
	length := len(b)
	for {
		if length == 0 {
			break
		}
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
	return
}

type aeadReader struct {
	io.Reader
	cipher.AEAD
	nonce   [32]byte
	buf     []byte
	offset  int
	iv      []byte
	sizeBuf []byte
	count   uint16
}

// AEADReader returns a aead reader
func AEADReader(r io.Reader, aead cipher.AEAD, iv []byte) io.Reader {
	return &aeadReader{Reader: r, AEAD: aead, iv: iv, sizeBuf: make([]byte, lenSize)}

}

func (r *aeadReader) Read(b []byte) (int, error) {
	if r.buf != nil {
		n := copy(b, r.buf[r.offset:])
		r.offset += n
		if r.offset == len(r.buf) {
			PutBuffer(r.buf)
			r.buf = nil
		}
		return n, nil
	}

	_, err := io.ReadFull(r.Reader, r.sizeBuf)
	if err != nil {
		return 0, err
	}

	size := int(binary.BigEndian.Uint16(r.sizeBuf))
	if size > maxSize {
		return 0, errors.New("buffer is larger than standard")
	}

	buf := GetBuffer(size)
	_, err = io.ReadFull(r.Reader, buf[:size])
	if err != nil {
		PutBuffer(buf)
		return 0, err
	}

	binary.BigEndian.PutUint16(r.nonce[:2], r.count)
	copy(r.nonce[2:], r.iv[2:12])

	_, err = r.Open(buf[:0], r.nonce[:r.NonceSize()], buf[:size], nil)
	r.count++
	if err != nil {
		return 0, err
	}
	realLen := size - r.Overhead()
	n := copy(b, buf[:realLen])
	if len(b) >= realLen {
		PutBuffer(buf)
		return n, nil
	}

	r.offset = n
	r.buf = buf[:realLen]
	return n, nil
}
