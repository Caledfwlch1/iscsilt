package main

import (
	"net"
	"strings"
	"errors"
	"fmt"
	//"math/big"
	//"encoding/asn1"
)

const (
	LenPacket 		= 1048510 // 2048

	OpCodeNOPOut		= "\x00"
	OpCodeSCSICommand	= "\x01"
	OpCodeSCSITaskReq	= "\x02"

	OpCodeTextReq		= "\x04"
	OpCodeSCSIDataOut	= "\x05"
	OpCodeLogoutReq 	= "\x06"
	OpCodeSNACKReq      	= "\x10"
	OpCodeNOPIn		= "\x20"
	OpCodeSCSIResp		= "\x21"
	OpCodeSCSITaskResp	= "\x22"
//	OpCodeLoginResp        	= "\x23"
	OpCodeTextResp		= "\x24"
	OpCodeSCSIDataIn	= "\x25"
	OpCodeLogoutResp       	= "\x26"
//	OpCodeReadyToTransfer  	= "\x31"
//	OpCodeAsyncMessage	= "\x32"
//	OpCodeReject		= "\x3f"
//	OpCodeImmed            	= "\x40"
//	OpCodeFinal		= "\x80"
//	TransitToNextLoginStage = "\x80"
//	TextIsComplete		= "\x40"
//	Status                  = "\x00\x00"

)
// tttaaa
type FieldPack struct {
	Begin	int
	Length	int
	Value	[]byte
}

func (v FieldPack)String() string {
	return fmt.Sprintf("v=%s (% x), b=%d, l=%d\n", v.Value, v.Value, v.Begin, v.Length)
}

var (
	OpCodeLoginReq		= byte(0x03)
	OpCodeImmed		= byte(0x40)
	TransitToNextLoginStage	= byte(0x80)
	OpCodeNSG		= byte(0x01)
	OpCodeCSG		= byte(0x00)
	OpCodeLoginResp		= byte(0x23)
	LROpCode		= FieldPack{ 0,2, []byte{0x00, 0x00}}
	LRVersionMax		= FieldPack{ 2,1, []byte{0x00}}
	LRVersionMin		= FieldPack{ 3,1, []byte{0x00}}
	LRTotalAHSLenght	= FieldPack{ 4,1, []byte{0x00}}
	LRDataSegmentLength	= FieldPack{ 5,3, []byte{0x00, 0x00, 0x00}}
	LRISID			= FieldPack{ 8,6, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	LRTSIH			= FieldPack{14,2, []byte{0x01, 0x00}}
	LRInitiatorTaskTag	= FieldPack{16,4, []byte{0x00, 0x00, 0x00, 0x01}}
	LRStatSN		= FieldPack{24,4, []byte{0x00, 0x00, 0x00, 0x00}}
	LRExpCmdSN		= FieldPack{28,4, []byte{0x00, 0x00, 0x00, 0x01}}
	LRMaxCmdSN		= FieldPack{32,4, []byte{0x00, 0x00, 0x00, 0x02}}
	LRStatusClass		= FieldPack{36,1, []byte{0x00}}
	LRStatusDetail		= FieldPack{37,1, []byte{0x00}}
	LRDataSegment		= FieldPack{48,0, []byte{}}

	ISID_t			= byte(0x40)
	ISID_a			= byte(0x00)
	ISID_b			= []byte{0x00, 0x01}
	ISID_c			= []byte{0x37}
	ISID_d			= []byte{0x00, 0x00}

	CID			= FieldPack{20,2, []byte{0x00, 0x00}}
	CmdSN			= FieldPack{24,4, []byte{0x00, 0x00, 0x00, 0x00}}

)

type BiteAnalize byte

func (v *BiteAnalize) BiteTestStrong(b byte) bool {
	return (*v & BiteAnalize(b)) == BiteAnalize(b)
}

func (v *BiteAnalize) BiteTestEntry(b byte) bool {
	return *v&BiteAnalize(b) == *v
}

func (v *BiteAnalize) BiteSet(b byte) {
	*v = BiteAnalize(b)
}

type ISCSIConnection struct {
	TCPConn *net.TCPConn
	OpCode	byte
	Packet	[]byte
	Param	map[string]string
}

func (c *ISCSIConnection) Read() error {
	b := make([]byte, LenPacket)
	c.Packet = make([]byte, 0)
	n, err := c.TCPConn.Read(b)
	c.Packet = b[:n]
	PrintDeb("Readed bytes = ", n)
	return err
}

func (c *ISCSIConnection) Write(b []byte) error {
	l := len(b)
	if l%2 > 0 {
		b = append(b, byte(0x00))
	}
	n, err := c.TCPConn.Write(b)
	PrintDeb("Writed bytes = ", n)
	return err
}

func (c ISCSIConnection) String() string {
	return strings.Replace(fmt.Sprintf("%s", c.Packet), "\x00", "\x20", -1)
}

func (c *ISCSIConnection) DecodeParam() {
	c.Param = make(map[string]string, 0)
	arrString := strings.Split(string(c.Packet[48:]), string("\x00"))
	for _, element := range arrString {
		if strings.Contains(element, "=") {
			p := strings.Split(element, "=")
			c.Param[p[0]] = p[1]
		}
	}
	return
}

func (c *ISCSIConnection)Get(v FieldPack) FieldPack {
	if len(c.Packet) < v.Begin+v.Length {
		v.Value = make([]byte, v.Length)
	} else {
		v.Value = c.Packet[v.Begin:v.Begin + v.Length]
	}
	return v
}

func (c *ISCSIConnection)loginCommandProc() (packWrite PacketBuild, err error) {

	dataSegment := []byte("TargetPortalGroupTag=1\x00AuthMethod=None\x00")
	dataSegmentLength := aligByte(string(len(dataSegment)), 3)
	LRDataSegmentLength.Value = []byte(dataSegmentLength)
	fmt.Println(LRDataSegmentLength)

	packWrite.New(48)
	LROpCode.Value =  []byte{OpCodeLoginResp, TransitToNextLoginStage | OpCodeNSG | OpCodeCSG}
	fmt.Println(LROpCode)

	packWrite.Set(LROpCode)
	packWrite.Set(LRVersionMax)
	packWrite.Set(LRVersionMin)
	packWrite.Set(LRTotalAHSLenght)
	packWrite.Set(LRDataSegmentLength)
	packWrite.Set(c.Get(LRISID))
	packWrite.Set(LRTSIH)
	packWrite.Set(LRInitiatorTaskTag)
	packWrite.Set(c.Get(CmdSN))
	packWrite.Set(LRExpCmdSN)
	packWrite.Set(LRMaxCmdSN)

	packWrite.Append(dataSegment)

	c.DecodeParam()

	if err := c.Write(packWrite.Packet); err != nil {
		PrintDeb(err)
		return packWrite, err
	}
	fmt.Printf("199 packWrite = % x\n %s\n", packWrite, packWrite)
	err = c.Read()
	if err != nil {
		return packWrite, err
	}
	PrintDeb(err)
	fmt.Printf("195 % x\n", c.Packet)

	if c.Packet[0] == OpCodeImmed | OpCodeLoginReq {
		PrintDeb("login Command II.")
	} else {
		PrintDeb("Unknown Command in login phase.")
		err = errors.New("Unknown Command in login phase.")
		return packWrite, err
	}

	return packWrite, err
}


func session(tcpConn *net.TCPConn) bool {
	var s ISCSIConnection
	//tcpConn.SetKeepAlive(true)
	//tcpConn.SetKeepAlivePeriod(time.Duration(5 * time.Second)) // !!!!!!!!!!!!!!!!!
	tcpConn.SetReadBuffer(1048510)
	tcpConn.SetWriteBuffer(1048510)
	s.TCPConn = tcpConn

	for i := 1; i <= 3; i++ {
		PrintDeb("---------", i, "---------")
		var bufWrite PacketBuild
		err := s.Read()
		fmt.Printf("197 ==> % x\n", s.Packet)
		PrintDeb(s)
		if err != nil {   // Error reading packet
			PrintDeb(err)
			continue
		}

		switch s.Packet[0] {
		case OpCodeImmed | OpCodeLoginReq:
			PrintDeb("login Command.")
			bufWrite, err = s.loginCommandProc()
			if err != nil {
				PrintDeb(err)
				break
			}
		default:
			PrintDeb("Unknown operation.")
		}

		if err := s.Write(bufWrite.Packet); err != nil {
			PrintDeb(err)
			continue
		}
	}
	s.TCPConn.Close()
	return true
}

type PacketBuild struct{
	Packet	[]byte
	maxSize	int
	Err	[]int
}

func (p *PacketBuild)New(n int) {
	p.maxSize = n
	p.Packet = make([]byte, n)
}

func (p *PacketBuild)Append(v []byte) {
	p.Packet = append(p.Packet, v...)
	p.SetMaxSize(len(p.Packet))
	return
}

func (p *PacketBuild)SetMaxSize(n int) {
	p.maxSize = n
}

func (p *PacketBuild)Set(v FieldPack) {
	if v.Begin + len(v.Value) > p.maxSize {
		p.Err = append(p.Err, v.Begin)
		return
	}
	_ = copy(p.Packet[v.Begin:], v.Value)
	return
}

func (p PacketBuild)String() string {
	return fmt.Sprintf("%s", p.Packet)
}
