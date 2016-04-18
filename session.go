package iscsilt

import (
	"net"
	"strings"
//	"errors"
	"fmt"
	//"math/big"
	//"encoding/asn1"
	"io"
	"os"
)

const (
	LenPacket 		= 1048510 // 2048

	OpCodeNOPOut		= "\x00"
	OpCodeSCSICommand	= "\x01"
	OpCodeSCSITaskReq	= "\x02"

//	OpCodeTextCommand	= "\x04"
	OpCodeSCSIDataOut	= "\x05"
	OpCodeLogoutReq 	= "\x06"
	OpCodeSNACKReq      	= "\x10"
	OpCodeNOPIn		= "\x20"
	OpCodeSCSIResp		= "\x21"
	OpCodeSCSITaskResp	= "\x22"
//	OpCodeLoginResp        	= "\x23"
//	OpCodeTextResp		= "\x24"
	OpCodeSCSIDataIn	= "\x25"
	OpCodeLogoutResp       	= "\x26"
//	OpCodeReadyToTransfer  	= "\x31"
//	OpCodeAsyncMessage	= "\x32"
//	OpCodeReject		= "\x3f"
//	OpCodeImmed            	= "\x40"
//	OpCodeFinal		= "\x80"
//	TransitToNextLoginStage = "\x80"
//	TextIsComplete		= "\x40"


)

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
	OpCodeLoginResp		= byte(0x23)
	OpCodeImmed		= byte(0x40)
	TransitToNextLoginStage	= byte(0x80)
	OpCodeNSG		= byte(0x03)
	OpCodeCSG		= byte(0x04)
	OpCodeTextCommand	= byte(0x04)
	OpCodeTextResp		= byte(0x24)
	LROpCode		= FieldPack{ 0,2, []byte{0x00, 0x00}}
	LRVersionMax		= FieldPack{ 2,1, []byte{0x00}}
	LRVersionMin		= FieldPack{ 3,1, []byte{0x00}}
	LRTotalAHSLenght	= FieldPack{ 4,1, []byte{0x00}}
	LRDataSegmentLength	= FieldPack{ 5,3, []byte{0x00, 0x00, 0x00}}
	LRISID			= FieldPack{ 8,6, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	LRTSIH			= FieldPack{14,2, []byte{0x01, 0x00}}
	LRInitiatorTaskTag	= FieldPack{16,4, []byte{0x00, 0x00, 0x00, 0x00}}
	LRStatSN		= FieldPack{24,4, []byte{0x00, 0x00, 0x00, 0x00}}
	LRExpCmdSN		= FieldPack{28,4, []byte{0x00, 0x00, 0x00, 0x01}}
	LRMaxCmdSN		= FieldPack{32,4, []byte{0x00, 0x00, 0x00, 0x02}}
	LRStatusClass		= FieldPack{36,1, []byte{0x00}}
	LRStatusDetail		= FieldPack{37,1, []byte{0x00}}
	LRDataSegment		= FieldPack{48,0, []byte{}}
	TCFlags			= FieldPack{ 1,1, []byte{0x80}}
	TCLUN			= FieldPack{ 8,8, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	TCTargetTransferTag	= FieldPack{20,4, []byte{0xff, 0xff, 0xff, 0xff}}
	TCStatSN		= FieldPack{24,4, []byte{0x00, 0x00, 0x00, 0x01}}
	TCExpCmdSN		= FieldPack{28,4, []byte{0x00, 0x00, 0x00, 0x02}}
	TCMaxCmdSN		= FieldPack{32,4, []byte{0x00, 0x00, 0x00, 0x03}}


	ISID_t			= byte(0x40)
	ISID_a			= byte(0x00)
	ISID_b			= []byte{0x00, 0x01}
	ISID_c			= []byte{0x37}
	ISID_d			= []byte{0x00, 0x00}

	CID			= FieldPack{20,2, []byte{0x00, 0x00}}


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

func (c *ISCSIConnection) InitParam() error {
	c.Param = make(map[string]string, 0)
	host, err := os.Hostname()
	if err == nil {
		c.Param["TargetName"] = "TargetName=iqn.2016-04.npp." + host + ":storage.lun1"
		PrintDeb(c.Param["TargetName"])
	} else {
		fmt.Println("It is impossible to determine the local hostname.")
	}
	ip := "172.24.1.3"
	if err == nil {
		c.Param["TargetAddress"] = "TargetAddress=172.24.1.3" + ip
		PrintDeb(c.Param["TargetAddress"])
	} else {
		fmt.Println("It is impossible to determine the local ip-address.")
	}
	return err
}

func (c *ISCSIConnection) Read() error {
	b := make([]byte, LenPacket)
	c.Packet = make([]byte, 0)
	// n, err := c.TCPConn.Read(b)
	n, err := io.ReadAtLeast(c.TCPConn, b, 48)
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
	// c.Param = make(map[string]string, 0)
	PrintDeb(c.Packet[48:])
	arrString := strings.Split(string(c.Packet[48:]) + string("\x00"), string("\x00"))
	PrintDeb(arrString, len(arrString))
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

func (c *ISCSIConnection)loginCommandProc() (err error) {
	var packWrite PacketBuild

	dataSegment := aligString(	"TargetPortalGroupTag=1\x00"+
					"HeaderDigest=None\x00"+
					"DataDigest=None\x00"+
					"DefaultTime2Wait=2\x00"+
					"DefaultTime2Retain=0\x00"+
					"IFMarker=No\x00"+
					"OFMarker=No\x00"+
					"ErrorRecoveryLevel=0\x00")
	dataSegmentLength := intToByte(len(dataSegment), 6)

	PrintDeb(dataSegmentLength)
	LRDataSegmentLength.Value = dataSegmentLength
	PrintDeb(LRDataSegmentLength)

	packWrite.New(48)
	LROpCode.Value =  []byte{OpCodeLoginResp, TransitToNextLoginStage | OpCodeNSG | OpCodeCSG}

	packWrite.Set(LROpCode)
	packWrite.Set(LRVersionMax)
	packWrite.Set(LRVersionMin)
	packWrite.Set(LRTotalAHSLenght)
	packWrite.Set(LRDataSegmentLength)
	packWrite.Set(c.Get(LRISID))
	packWrite.Set(LRTSIH)
	packWrite.Set(LRInitiatorTaskTag)
	packWrite.Set(LRStatSN)
	packWrite.Set(LRExpCmdSN)
	packWrite.Set(LRMaxCmdSN)
	packWrite.Set(LRStatusClass)
	packWrite.Set(LRStatusDetail)

	packWrite.Append(dataSegment)

	c.DecodeParam()

	if err := c.Write(packWrite.Packet); err != nil {
		PrintDeb(err)
		return err
	}
	return err
}

func (c *ISCSIConnection)textCommand() (err error) {
	var packWrite PacketBuild
	var dataSegment []byte
	c.DecodeParam()

	if c.Param["SendTargets"] == "All" {
		dataSegment = aligString("TargetName=iqn.2016-04.npp.sit-1920:storage.lun1\x00TargetAddress=172.24.1.3:3260,1")
	} else {
		PrintDeb(c.Param["SendTargets"])
		dataSegment = aligString("TargetName=None\x00"+
					"TargetAddress=None\x00")
	}
	dataSegmentLength := intToByte(len(dataSegment), 6)
	LRDataSegmentLength.Value = []byte(dataSegmentLength)

	packWrite.New(48)
	LROpCode.Value =  []byte{OpCodeTextResp}
	packWrite.Set(LROpCode)
	packWrite.Set(TCFlags)
	packWrite.Set(LRTotalAHSLenght)
	packWrite.Set(LRDataSegmentLength)
	packWrite.Set(TCLUN)
	LRInitiatorTaskTag.Value = []byte{0x00, 0x00, 0x00, 0x01}
	packWrite.Set(c.Get(LRInitiatorTaskTag))
	packWrite.Set(TCTargetTransferTag)
	packWrite.Set(TCStatSN)
	packWrite.Set(TCExpCmdSN)
	packWrite.Set(TCMaxCmdSN)

	packWrite.Append(dataSegment)
	PrintDeb(packWrite.Packet)
	if err := c.Write(packWrite.Packet); err != nil {
		PrintDeb(err)
		return err
	}
	return err
}

func session(tcpConn *net.TCPConn) bool {
	var s ISCSIConnection
	//tcpConn.SetKeepAlive(true)
	//tcpConn.SetKeepAlivePeriod(time.Duration(5 * time.Second)) // !!!!!!!!!!!!!!!!!
	tcpConn.SetReadBuffer(1048510)
	tcpConn.SetWriteBuffer(1048510)
	s.TCPConn = tcpConn
	if s.InitParam() != nil {
		return true
	}

	for i := 1; i <= 4; i++ {
		PrintDeb("---------", i, "---------")
		err := s.Read()

		if err != nil {   // Error reading packet
			PrintDeb(err)
			continue
		}

		switch s.Packet[0] {
		case OpCodeImmed | OpCodeLoginReq:
			PrintDeb("login Command.")
			err = s.loginCommandProc()
			if err != nil {
				PrintDeb(err)
				break
			}
		case OpCodeTextCommand:
			PrintDeb("Text Command.")
			err = s.textCommand()
			if err != nil {
				PrintDeb(err)
				break
			}
		default:
			PrintDeb("Unknown operation.")
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

