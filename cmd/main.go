package main

import "iscsilt"

func main() {
	var config iscsilt.ConfType

	config.IP = "172.24.1.3"

	iscsilt.ISCSIlt(config)
}
