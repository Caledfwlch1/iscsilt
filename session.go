package iscsilt

// interface version

import (
	"net"
	"strings"
	"fmt"
	"io"
	"os"
	//"container/list"
)

const (
	LenPacket 		= 2048 //   1048510

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

const (
	InitConnection	= iota
	LoginPhase
	TextCommandPhase
	LogOutPhase
	CloseConnection
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
	Param	map[string]string
	Phase	int
}

type Packet struct {
	P	[]byte
	L	int
}

func (p *Packet)FullPack() []byte {
	return p.P[:p.L]
}

func (p *Packet)DataPack() []byte {
	return p.P[48:p.L]
}

func (p Packet)String() string {
	return "P = " + string(p.P) + "\nL = " + fmt.Sprint(p.L)
}

func (c *ISCSIConnection) ReadFrom(p *Packet) (error) {
	p.P = make([]byte, LenPacket)
	n, err := io.ReadAtLeast(c.TCPConn, p.P, 49)
	p.L = n
	PrintDeb("Readed bytes = ", p.L)
	return err
}

func (c *ISCSIConnection) WriteTo(p *Packet) (int, error) {
	if p.L%2 > 0 {
		p.L++
	}
	n, err := c.TCPConn.Write(p.FullPack())
	PrintDeb("Writed bytes = ", n)
	return n, err
}


func (c *ISCSIConnection)DecodeParam(p *Packet) {


	arrString := strings.Split(string(p.DataPack()) + string("\x00"), string("\x00"))

	for _, element := range arrString {
		if strings.Contains(element, "=") {
			ar := strings.Split(element, "=")
			c.Param[ar[0]] = ar[1]
		}
	}
	return
}

func (c *ISCSIConnection)Get(p []byte, v FieldPack) FieldPack {
	if len(p) < v.Begin+v.Length {
		v.Value = make([]byte, v.Length)
	} else {
		v.Value = p[v.Begin:v.Begin + v.Length]
	}
	return v
}

func (c *ISCSIConnection)loginCommandProc(bufin, bufout *Packet) {
	var packWrite PacketBuild

	c.Phase = LoginPhase

	dataSegment := aligString(	"TargetPortalGroupTag=1\x00"+
					"HeaderDigest=None\x00"+
					"DataDigest=None\x00"+
					"DefaultTime2Wait=2\x00"+
					"DefaultTime2Retain=0\x00"+
					"IFMarker=No\x00"+
					"OFMarker=No\x00"+
					"ErrorRecoveryLevel=0\x00")
	dataSegmentLength := intToByte(len(dataSegment), 6)

	LRDataSegmentLength.Value = dataSegmentLength

	packWrite.New(bufout, 48+ len(dataSegment))
	LROpCode.Value =  []byte{OpCodeLoginResp, TransitToNextLoginStage | OpCodeNSG | OpCodeCSG}

	packWrite.Set(LROpCode)
	packWrite.Set(LRVersionMax)
	packWrite.Set(LRVersionMin)
	packWrite.Set(LRTotalAHSLenght)
	packWrite.Set(LRDataSegmentLength)
	packWrite.Set(c.Get(bufin.FullPack(), LRISID))
	packWrite.Set(LRTSIH)
	packWrite.Set(LRInitiatorTaskTag)
	packWrite.Set(LRStatSN)
	packWrite.Set(LRExpCmdSN)
	packWrite.Set(LRMaxCmdSN)
	packWrite.Set(LRStatusClass)
	packWrite.Set(LRStatusDetail)
	LRDataSegment.Value = dataSegment
	packWrite.Set(LRDataSegment)
	bufout.L = 48 + len(dataSegment)

	c.DecodeParam(bufin)

	return
}

func (c *ISCSIConnection)textCommand(bufin, bufout *Packet) {
	var packWrite PacketBuild
	var dataSegment []byte
	c.Phase = TextCommandPhase

	c.DecodeParam(bufin)

	if c.Param["SendTargets"] == "All" {
		dataSegment = aligString("TargetName=iqn.2016-04.npp.sit-1920:storage.lun1\x00TargetAddress=172.24.1.3:3260,1")
	} else {
		dataSegment = aligString("TargetName=None\x00"+
					"TargetAddress=None\x00")
	}
	dataSegmentLength := intToByte(len(dataSegment), 6)
	LRDataSegmentLength.Value = []byte(dataSegmentLength)

	packWrite.New(bufout, 48 + len(dataSegment))
	LROpCode.Value =  []byte{OpCodeTextResp}
	packWrite.Set(LROpCode)
	packWrite.Set(TCFlags)
	packWrite.Set(LRTotalAHSLenght)
	packWrite.Set(LRDataSegmentLength)
	packWrite.Set(TCLUN)
	LRInitiatorTaskTag.Value = []byte{0x00, 0x00, 0x00, 0x01}
	packWrite.Set(c.Get(bufin.FullPack(), LRInitiatorTaskTag))
	packWrite.Set(TCTargetTransferTag)
	packWrite.Set(TCStatSN)
	packWrite.Set(TCExpCmdSN)
	packWrite.Set(TCMaxCmdSN)
	LRDataSegment.Value = dataSegment
	packWrite.Set(LRDataSegment)

	return
}

func New(tcpConn *net.TCPConn) (c ISCSIConnection) {
	c.Phase = InitConnection
	c.TCPConn = tcpConn
	c.Param = make(map[string]string, 0)
	host, err := os.Hostname()
	if err != nil {
		host = "localhost"
	}
	c.Param["TargetName"] = "TargetName=iqn.2016-04.npp." + host + ":storage.lun1"
	c.Param["TargetAddress"] = "TargetAddress=" + c.TCPConn.LocalAddr().String()




	return c
}

func session(tcpConn *net.TCPConn) bool {
	var bufin, bufout Packet

	PrintDeb("Run session!")
	bufin.P  = make([]byte, LenPacket)
	bufout.P = make([]byte, LenPacket)
	s := New(tcpConn)
	i := 1
	for s.Phase != CloseConnection && i<5{
		i++
		PrintDeb("---------", s.Phase, "---------")

		err := s.ReadFrom(&bufin)
		if err != nil {   // Error reading packet
			PrintDeb(err)
			continue
		}
		s.procPacket(&bufin, &bufout)

		_, err = s.WriteTo(&bufout)
		if err != nil {
			PrintDeb(err)
			break
		}

	}
	tcpConn.Close()
	return true
}

func (c *ISCSIConnection)procPacket(bufin, bufout *Packet) {
	switch bufin.P[0] {
	case OpCodeImmed | OpCodeLoginReq:
		PrintDeb("login Command.")
		 c.loginCommandProc(bufin, bufout)
	case OpCodeTextCommand:
		PrintDeb("Text Command.")
		c.textCommand(bufin, bufout)
	default:
		PrintDeb("Unknown operation.")
	}
	return
}

type PacketBuild struct{
	Packet	[]byte
	maxSize	int
	Err	[]int
}

func (p *PacketBuild)New(buf *Packet, n int) {
	p.maxSize = n
	p.Packet = buf.P
}

func (p *PacketBuild)SetMaxSize(n int) {
	p.maxSize = n
	return
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

/*
func (p *PacketBuild)Append(v []byte) {
	*p.Packet = append(*p.Packet, v...)
	p.SetMaxSize(len(*p.Packet))
	return
}

func (p *PacketBuild)AlignPacket(n int) {
	l := n%2
	if l > 0 {
		l++
	}
	a := *p.Packet
	a = a[:48 + l]
	p.Packet = &a
	return
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

func readPack(c *net.TCPConn, buf []byte) error {
	n, err := io.ReadAtLeast(c, buf, 48)
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
func writePack(c *net.TCPConn, buf []byte) error {
	l := len(buf)
	if l%2 > 0 {
		buf = append(buf, byte(0x00))
	}
	n, err := c.Write(buf)
	PrintDeb("Writed bytes = ", n)
	return err
} */
/*
func (c ISCSIConnection) String() string {
	return strings.Replace(fmt.Sprintf("%s", c.Packet), "\x00", "\x20", -1)
} */


