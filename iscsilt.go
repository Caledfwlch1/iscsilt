// iscsilt
package iscsilt

import (
	"fmt"
	"net"
)

type ConfType struct {
	IP	string
}

func ISCSIlt(conf ConfType) {
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
		if err != nil {
			PrintDeb(err)
			return
		}
		// go session(tcpConn)
		if session(tcpConn) {
			break
		}
	}

}

