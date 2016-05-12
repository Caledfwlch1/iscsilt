// iscsilt
package iscsilt

// interface version

import (
	"fmt"
	"net"
)

type ConfType struct {
	IP	string
}

func ListenISCSI(conf ConfType) {
	var ipForListen = net.TCPAddr{net.ParseIP(conf.IP), 3260, ""}
	fmt.Println("Start")
	listen, err := net.ListenTCP("tcp", &ipForListen)
	defer listen.Close()
	if err != nil {
		PrintDeb(err)
		return
	}

	for {
		tcpConn, err := listen.AcceptTCP()
		//tcpConn.SetKeepAlive(true)
		//tcpConn.SetKeepAlivePeriod(time.Duration(5 * time.Second)) // !!!!!!!!!!!!!!!!!
		tcpConn.SetReadBuffer(LenPacket)
		tcpConn.SetWriteBuffer(LenPacket)
		if err != nil {
			PrintDeb(err)
			return
		}
		// go session(tcpConn)

		if session(tcpConn) {
			break
		}
	}
	return
}
