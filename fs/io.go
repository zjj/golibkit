package fs

import (
	"io"
	"syscall"
)

func SafeWriteAllData(w io.Writer, data []byte) (err error) {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			if err == syscall.EAGAIN || err == syscall.EWOULDBLOCK {
				continue
			}
			return err
		}
		data = data[n:]
	}
	return nil
}
