package iscsilt

// interface version

import (
	"fmt"
	"encoding/binary"
//	"bytes"
	"io"
//	"bufio"
	"strings"
	"net"
	"errors"
)

const (
	LenPacket 		= 2048		//   1048510
	OpCodeSCSICommand	= byte(0x01)	// Operation code SCSI Command
	OpCodeSCSICommandResp	= byte(0x21)	// Operation code SCSI Command Response
	OpCodeLoginReq		= byte(0x03)	// Operation code Login Request
	OpCodeLoginResp        	= byte(0x23)	// Operation code Login Response
	OpCodeTextCommand	= byte(0x04)	// Operation code Text Command Request
	OpCodeTextResp		= byte(0x24)	// Operation code Text Command Response
)

var (
	TransitToNextLoginStage	= byte(0x80)
	OpCodeNSG		= byte(0x03)
	OpCodeCSG		= byte(0x04)

	LROpCode		= FieldPack{ 0,2, []byte{0x00, 0x00}}
	LRVersionMax		= FieldPack{ 2,1, []byte{0x00}}
	LRVersionMin		= FieldPack{ 3,1, []byte{0x00}}
	LRVersionActive		= FieldPack{ 3,1, []byte{0x00}}
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
)

type ISCSIConnection struct {
	Header	ISCSIHeader
	DS	map[string]string	// Login parameters
	DataR	[]byte			// Data read from ...
	DataW	[]byte			// Data write to ...
}

type ISCSIHeader struct {
	Raw		[48]byte
	OpCode		byte		// Operation code
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes Data segmetnt length
	msg		Msg
}

type FieldPack struct {
	Begin	int
	Length	int
	Value	[]byte
}

type LoginHeader struct {
	OpCode		byte		// 1 byte
	OpCodeSF	byte		// 1 byte OpCodeSpcField
	I		bool		// Immediate bit
	T		bool		// Transit bit
	C		bool		// Continue bit
	CSG		int		// Current stage
	NSG		int		// Next stage
	VerMax		byte		// 1 byte
	VerMin		byte		// 1 byte
	VerActive	byte		// 1 byte
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes
	ISID		[6]byte		// 6 bytes
	TSIH		[2]byte		// 2 bytes
	InitTaskTag	[4]byte		// 4 bytes
	CID		[2]byte		// 2 bytes
	CmdSN		int		// 4 bytes
	StatSN		[4]byte		// 4 bytes
	ExpStatSN	int		// 4 bytes
	ExpCmdSN	[4]byte		// 4 bytes
	MaxCmdSN	[4]byte		// 4 bytes
	StatusClass	byte		// 1 byte
	StatusDetail	byte		// 1 byte
	DataW		[]byte
	msg		Msg
}

type TextHeader struct {
	Header		[48]byte	// Header of the packet
	OpCode		byte		// 1 byte
	OpCodeSF	byte		// 1 byte OpCodeSpcField
	I		bool		// Immediate bit
	F		bool		// Final bit
	C		bool		// Continue bit
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes
	LUN		[8]byte		// 8 bytes
	InitTaskTag	[4]byte		// 4 bytes
	TargetTransTag	[4]byte		// 4 bytes
	CmdSN		int		// 4 bytes
	ExpStatSN	int		// 4 bytes
	msg		Msg
}

var _ Msg = (*LoginHeader)(nil)

type Msg interface {
	ReadFrom(io.Reader) (int, error)
	WriteTo(io.Writer) (int, error)
}

func session(tcpConn *net.TCPConn) bool {
	var p ISCSIConnection

	for {
		n, err := p.ReadFrom(tcpConn)
		PrintDeb("n=", n, " err=", err, " p=", p)
		if err != nil {
			break
		}
		n, err = p.WriteTo(tcpConn)
		PrintDeb("n=", n, " err=", err) //, "\n65 - p=", p)
	}

	return true
}

func NewReader(h ISCSIHeader) *ISCSIHeader {
	return &h
}

func (p *ISCSIConnection)ReadFrom(r io.Reader) (int, error) {
	var lh LoginHeader
	var tc TextHeader
	p.DS = make(map[string]string, 0)
	n, err := p.Header.ReadFrom(r)
	if err != nil || n == 0{
		return n, err
	}
	PrintDeb(p.Header.Raw)
	p.DataR = make([]byte, 48 + p.Header.DataSegLen)
	switch p.Header.OpCode {
	case OpCodeLoginReq:
		PrintDeb("login Command.")
		n, err = lh.ReadFrom(NewReader(p.Header))
		//n, err = io.ReadFull(r, p.DataR)
		n, err = io.ReadAtLeast(r, p.DataR, p.Header.DataSegLen)
		DecodeData(p.DataR, p.DS)
		p.loginResponce(lh)
	case OpCodeTextCommand:
		PrintDeb("Text Command.")
		n, err = tc.ReadFrom(NewReader(p.Header))
		// n, err = io.ReadFull(r, p.DataR)
		n, err = io.ReadAtLeast(r, p.DataR, p.Header.DataSegLen)
		DecodeData(p.DataR, p.DS)
		p.textResponce(tc)
	default:
		PrintDeb("Unknown operation.")
		err = errors.New("Unknown operation.")
	}

	return n, err
}

func (p *ISCSIConnection)loginResponce(lh LoginHeader) {
	dataSegment := aligString(	"TargetPortalGroupTag=1\x00"+
	"HeaderDigest=None\x00"+
	"DataDigest=None\x00"+
	"DefaultTime2Wait=2\x00"+
	"DefaultTime2Retain=0\x00"+
	"IFMarker=No\x00"+
	"OFMarker=No\x00"+
	"ErrorRecoveryLevel=0\x00")
	dataSegmentLength := intToByte(len(dataSegment), 6)

	p.DataW = make([]byte, 48 + len(dataSegment))

	LROpCode.Value = []byte{OpCodeLoginResp, TransitToNextLoginStage | OpCodeNSG | OpCodeCSG}
	p.Set(LROpCode)

	p.Set(LRVersionMax)
	p.Set(LRVersionActive)

	LRTotalAHSLenght.Value = []byte{0x00}
	p.Set(LRTotalAHSLenght)

	LRDataSegmentLength.Value = dataSegmentLength
	p.Set(LRDataSegmentLength)

	LRISID.Value = lh.ISID[:]
	p.Set(LRISID)

	LRTSIH.Value = []byte{0x01, 0x00}
	p.Set(LRTSIH)

	LRInitiatorTaskTag.Value = []byte{0x00, 0x00, 0x00, 0x00}
	p.Set(LRInitiatorTaskTag)

	LRStatSN.Value = []byte{0x00, 0x00, 0x00, 0x00}
	p.Set(LRStatSN)

	LRExpCmdSN.Value = []byte{0x00, 0x00, 0x00, 0x01}
	p.Set(LRExpCmdSN)

	LRMaxCmdSN.Value = []byte{0x00, 0x00, 0x00, 0x02}
	p.Set(LRMaxCmdSN)

	LRStatusClass.Value = []byte{0x00}
	p.Set(LRStatusClass)

	LRStatusDetail.Value = []byte{0x00}
	p.Set(LRStatusDetail)

	LRDataSegment.Value = dataSegment
	p.Set(LRDataSegment)

	return
}

func (p *ISCSIConnection)Set(v FieldPack) {
	_ = copy(p.DataW[v.Begin:], v.Value)
	return
}

func (p *ISCSIConnection)textResponce(tc TextHeader) {
	var dataSegment []byte

	if p.DS["SendTargets"] == "All" {
		dataSegment = aligString("TargetName=iqn.2016-04.npp.sit-1920:storage.lun1\x00TargetAddress=172.24.1.3:3260,1")
	} else {
		dataSegment = aligString("TargetName=None\x00"+
		"TargetAddress=None\x00")
	}
	dataSegmentLength := intToByte(len(dataSegment), 6)
	LRDataSegmentLength.Value = []byte(dataSegmentLength)
	p.DataW = make([]byte, 48 + len(dataSegment))

	LROpCode.Value =  []byte{OpCodeTextResp}
	p.Set(LROpCode)
	p.Set(TCFlags)
	p.Set(LRTotalAHSLenght)
	p.Set(LRDataSegmentLength)
	p.Set(TCLUN)
	LRInitiatorTaskTag.Value = tc.InitTaskTag[:]
	p.Set(LRInitiatorTaskTag)
	p.Set(TCTargetTransferTag)
	p.Set(TCStatSN)
	p.Set(TCExpCmdSN)
	p.Set(TCMaxCmdSN)
	LRDataSegment.Value = dataSegment
	p.Set(LRDataSegment)

	return
}

func (h *ISCSIHeader)Read(p []byte) (n int, err error) {
	n = copy(p, h.Raw[:])
	return n, err
}

func (p *LoginHeader)ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 48)
	n, err := io.ReadFull(r, buf)

	p.I		= selectBit((buf[0]), 0x40)
	p.OpCode 	= buf[0] & 0x3f
	p.OpCodeSF	= buf[1]
	p.T		= selectBit(p.OpCodeSF, 0x80)
	p.C		= selectBit(p.OpCodeSF, 0x40)
	p.CSG		= int(binary.BigEndian.Uint16([]byte{0, selectBits(p.OpCodeSF, 0x0c)}))
	p.NSG		= int(binary.BigEndian.Uint16([]byte{0, selectBits(p.OpCodeSF, 0x03)}))
	p.VerMax	= buf[2]
	p.VerMin	= buf[3]
	p.TotAHSLen	= int(binary.BigEndian.Uint16([]byte{0, buf[4]}))
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, buf[5:8]...)))
	_ = copy(p.ISID[:], buf[8:14])
	_ = copy(p.TSIH[:], buf[14:16])
	_ = copy(p.InitTaskTag[:], buf[16:20])
	_ = copy(p.CID[:], buf[20:22])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))

	return n, err
}

func (p *ISCSIHeader)ReadFrom(r io.Reader) (int, error) {
	n, err := io.ReadFull(r, p.Raw[:])
	p.OpCode = p.Raw[0] & 0x3f
	p.TotAHSLen	= int(binary.BigEndian.Uint16([]byte{0, p.Raw[4]}))
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, p.Raw[5:8]...)))
	return n, err
}


func (p *TextHeader)ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 48)
	n, err := io.ReadFull(r, buf)

	p.I		= selectBit((buf[0]), 0x40)
	p.OpCode 	= buf[0] & 0x3f
	p.OpCodeSF	= buf[1]
	p.F		= selectBit(p.OpCodeSF, 0x80)
	p.C		= selectBit(p.OpCodeSF, 0x40)
	p.TotAHSLen	= int(binary.BigEndian.Uint16([]byte{0, buf[4]}))
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, buf[5:8]...)))
	_ = copy(p.LUN[:], buf[8:16])
	_ = copy(p.InitTaskTag[:], buf[16:20])
	_ = copy(p.TargetTransTag[:], buf[20:24])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))

	return n, err
}

func DecodeData(buf []byte, ds map[string]string) {

	arrString := strings.Split(string(buf), string("\x00"))
	for _, element := range arrString {
		if strings.Contains(element, "=") {
			ar := strings.Split(element, "=")
			ds[ar[0]] = ar[1]
		}
	}
	return
}

func selectBit(bi, bc byte) (bool) {
	return (bi & bc) == bc
}

func selectBits(bi, bc byte) (byte) {
	return (bi & bc)
}

func (p ISCSIConnection)String() (string) {
	out := ""
	for i, j := range p.DS {
		out += " " + fmt.Sprint(i) + "=" + fmt.Sprint(j)
	}
	return fmt.Sprintf("Param=%s, \nDataW=%s", out, p.DataW)
}

func (p LoginHeader)String() (string) {
	return fmt.Sprintf("p.OpCode=%x, p.OpCodeSF=%x, p.I=%t, p.T=%t, p.C=%t, p.CSG=%d, p.NSG=%d, p.VerMax=%x, p.VerMin=%x, p.TotAHSLen=%d,"+
	" p.DataSegLen=%d, p.ISID=%x, p.TSIH=%x, p.InitTaskTag=%x, p.CID=%x, p.CmdSN=%d,"+
	" p.ExpStatSN=%d",
		p.OpCode, p.OpCodeSF, p.I, p.T, p.C, p.CSG, p.NSG, p.VerMax, p.VerMin, p.TotAHSLen,
		p.DataSegLen, p.ISID, p.TSIH, p.InitTaskTag, p.CID, p.CmdSN,
		p.ExpStatSN)
}

func (p TextHeader)String() (string) {
	return fmt.Sprintf("OpCode=%x, OpCodeSF=%x, I=%t, F=%t, C=%t, TotAHSLen=%d, DataSegLen=%d, LUN=%x, InitTaskTag=%x, TargetTransTag=%x, CmdSN=%d, ExpStatSN=%d",
		p.OpCode, p.OpCodeSF, p.I, p.F, p.C, p.TotAHSLen, p.DataSegLen, p.LUN, p.InitTaskTag, p.TargetTransTag, p.CmdSN, p.ExpStatSN)
}

func (p *ISCSIConnection)WriteTo(w io.Writer) (int, error) {
	//p.MakePacket()
	n, err := w.Write(p.DataW)
	return n, err
}

func (p *LoginHeader)WriteTo(w io.Writer) (int, error) {
	n, err := w.Write(p.DataW)
	return n, err
}

func (p *ISCSIHeader)WriteTo(w io.Writer) (int, error) {
	n, err := w.Write(p.Raw[:])
	return n, err
}
/*
func (p *ISCSIConnection)MakePacket() {
	p.DataW = []byte{0x43, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7,
		0x00, 0x02, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return
}
*/

