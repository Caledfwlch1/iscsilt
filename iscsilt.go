// iscsilt
package main

import (
	"fmt"
	"net"
)

// tttaaa
func main() {
	var ipForListen = net.TCPAddr{net.ParseIP("0.0.0.0"), 3260, ""}
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

