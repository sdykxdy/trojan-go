package vmess

import (
	"encoding/binary"
	"errors"
	"github.com/sdykxdy/trojan-go/common/pool"
	"io"
	"math/rand"
)

const (
	lenSize   = 2
	chunkSize = 1 << 14   // 2 ** 14 == 16 * 1024
	maxSize   = 17 * 1024 // 2 + chunkSize + aead.Overhead()
	padSize   = 1 << 16
)

type chunkReader struct {
	io.Reader
	buf         []byte
	sizeBuf     []byte
	offset      int
	shakeParser *ShakeSizeParser
}

func newChunkReader(reader io.Reader, shakeParser *ShakeSizeParser) *chunkReader {
	return &chunkReader{Reader: reader, sizeBuf: make([]byte, lenSize), shakeParser: shakeParser}
}

func newChunkWriter(writer io.WriteCloser, shakeParser *ShakeSizeParser) *chunkWriter {
	return &chunkWriter{Writer: writer, shakeParser: shakeParser}
}

func (cr *chunkReader) Read(b []byte) (int, error) {
	if cr.buf != nil {
		n := copy(b, cr.buf[cr.offset:])
		cr.offset += n
		if cr.offset == len(cr.buf) {
			pool.Put(cr.buf)
			cr.buf = nil
		}
		return n, nil
	}

	_, err := io.ReadFull(cr.Reader, cr.sizeBuf)
	if err != nil {
		return 0, err
	}

	// size = readLen + Overhead()
	var size int
	// 填充数据长度
	var paddingLen uint16
	// totalsize = size + paddingLen
	var totalsize uint16
	if cr.shakeParser != nil {
		paddingLen = cr.shakeParser.NextPaddingLen()
		totalsize, err = cr.shakeParser.Decode(cr.sizeBuf)
		if err != nil {
			return 0, err
		}
		size = int(totalsize - paddingLen)
	} else {
		size = int(binary.BigEndian.Uint16(cr.sizeBuf))
	}
	if size > maxSize && cr.shakeParser == nil {
		return 0, errors.New("buffer is larger than standard")
	}

	//if len(b) >= size {
	//	_, err := io.ReadFull(cr.Reader, b[:size])
	//	if err != nil {
	//		return 0, err
	//	}
	//
	//	return size, nil
	//}
	// 把所有的数据读出来
	size = size + int(paddingLen)

	buf := pool.Get(size)
	_, err = io.ReadFull(cr.Reader, buf)
	if err != nil {
		pool.Put(buf)
		return 0, err
	}
	realLen := size - int(paddingLen)
	n := copy(b, buf[:realLen])
	cr.offset = n
	cr.buf = buf[:realLen]
	return n, nil
}

type chunkWriter struct {
	io.Writer
	shakeParser *ShakeSizeParser
}

func (cw *chunkWriter) Write(b []byte) (n int, err error) {
	buf := pool.Get(pool.RelayBufferSize)
	defer pool.Put(buf)
	length := len(b)
	for {
		if length == 0 {
			break
		}
		if cw.shakeParser != nil {
			paddingSize := int(cw.shakeParser.NextPaddingLen())
			readLen := chunkSize
			if length < chunkSize {
				readLen = length
			}
			payloadBuf := buf[lenSize : lenSize+chunkSize]

			copy(payloadBuf, b[n:n+readLen-paddingSize])
			if paddingSize > 0 {
				rand.Read(payloadBuf[lenSize+readLen-paddingSize:])
			}
			cw.shakeParser.Encode(uint16(readLen), buf[:lenSize])

			//binary.BigEndian.PutUint16(buf[:lenSize], uint16(readLen))
			_, err = cw.Writer.Write(buf[:lenSize+readLen])
			if err != nil {
				break
			}
			n += readLen
			length -= readLen
		} else {
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

	}
	return
}
