package vmess

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	lenSize   = 2
	chunkSize = 1 << 14   // 16384
	maxSize   = 17 * 1024 // 2 + chunkSize + aead.Overhead()
)

type chunkedWriter struct {
	io.Writer
}

// ChunkedWriter returns a chunked writer
func ChunkedWriter(w io.Writer) io.Writer {
	return &chunkedWriter{Writer: w}
}

func (cw *chunkedWriter) Write(b []byte) (n int, err error) {
	buf := GetBuffer(RelayBufferSize)
	defer PutBuffer(buf)
	length := len(b)
	for {
		if length == 0 {
			break
		}
		readLen := chunkSize
		if length < chunkSize {
			readLen = length
		}
		payloadBuf := buf[lenSize : lenSize+chunkSize]
		copy(payloadBuf, b[n:n+readLen])

		binary.BigEndian.PutUint16(buf[:lenSize], uint16(readLen))
		_, err = cw.Writer.Write(buf[:lenSize+readLen])
		if err != nil {
			break
		}
		n += readLen
		length -= readLen
	}
	return
}

type chunkedReader struct {
	io.Reader
	buf     []byte
	sizeBuf []byte
	offset  int
}

// ChunkedReader returns a chunked reader
func ChunkedReader(r io.Reader) io.Reader {
	return &chunkedReader{Reader: r, sizeBuf: make([]byte, lenSize)}
}

func (cr *chunkedReader) Read(b []byte) (int, error) {
	if cr.buf != nil {
		n := copy(b, cr.buf[cr.offset:])
		cr.offset += n
		if cr.offset == len(cr.buf) {
			PutBuffer(cr.buf)
			cr.buf = nil
		}
		return n, nil
	}

	_, err := io.ReadFull(cr.Reader, cr.sizeBuf)
	if err != nil {
		return 0, err
	}

	size := int(binary.BigEndian.Uint16(cr.sizeBuf))
	if size > maxSize {
		return 0, errors.New("buffer is larger than standard")
	}

	if len(b) >= size {
		_, err := io.ReadFull(cr.Reader, b[:size])
		if err != nil {
			return 0, err
		}

		return size, nil
	}

	buf := GetBuffer(size)
	_, err = io.ReadFull(cr.Reader, buf)
	if err != nil {
		PutBuffer(buf)
		return 0, err
	}
	n := copy(b, buf)
	cr.offset = n
	cr.buf = buf
	return n, nil
}
