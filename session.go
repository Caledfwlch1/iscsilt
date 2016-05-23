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
	OpCodeDataIn		= byte(0x25)	// Operation code SCSI Data In Response


	FinalTrue		= byte(0x80)	// Final bit - 1
	FinalFalse		= byte(0x00)	// Final bit - 0
	AcknowledgeTrue		= byte(0x40)	// Acknowledge bit - 1
	AcknowledgeFalse	= byte(0x00)	// Acknowledge bit - 0
	ResidualOverflowTrue	= byte(0x04)	// Residual Overflow bit - 1
	ResidualOverflowFalse	= byte(0x00)	// Residual Overflow bit - 0
	ResidualUnOverflowTrue	= byte(0x02)	// Residual UnOverflow bit - 1
	ResidualUnOverflowFalse	= byte(0x00)	// Residual UnOverflow bit - 0
	StatusBitTrue		= byte(0x01)	// Status bit - 1
	StatusBitFalse		= byte(0x00)	// Status bit - 0
)

var (
	TransitToNextLoginStage	= byte(0x80)
	OpCodeNSG		= byte(0x03)
	OpCodeCSG		= byte(0x04)

	ROpCode			= FieldPack{ 0,2, []byte{0x00, 0x00}}
	RVersionMax		= FieldPack{ 2,1, []byte{0x00}}
//	RVersionMin		= FieldPack{ 3,1, []byte{0x00}}
	RVersionActive		= FieldPack{ 3,1, []byte{0x00}}
	StatusField		= FieldPack{ 3,1, []byte{0x00}}
	RTotalAHSLenght		= FieldPack{ 4,1, []byte{0x00}}
	RDataSegmentLength	= FieldPack{ 5,3, []byte{0x00, 0x00, 0x00}}
	RISID			= FieldPack{ 8,6, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00}}
	RTSIH			= FieldPack{14,2, []byte{0x01, 0x00}}
	RInitiatorTaskTag	= FieldPack{16,4, []byte{0x00, 0x00, 0x00, 0x00}}
	RStatSN			= FieldPack{24,4, []byte{0x00, 0x00, 0x00, 0x00}}
	RExpCmdSN		= FieldPack{28,4, []byte{0x00, 0x00, 0x00, 0x01}}
	RMaxCmdSN		= FieldPack{32,4, []byte{0x00, 0x00, 0x00, 0x02}}
	RStatusClass		= FieldPack{36,1, []byte{0x00}}
	RStatusDetail		= FieldPack{37,1, []byte{0x00}}
	RDataSegment		= FieldPack{48,0, []byte{}}
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

type FieldPack struct {
	Begin	int
	Length	int
	Value	[]byte
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
	var sc SCSIHeader
	p.DS = make(map[string]string, 0)
	n, err := p.Header.ReadFrom(r)
	if err != nil || n < 48 {
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
		p.Decode()
		p.loginResponce(lh)
	case OpCodeTextCommand:
		PrintDeb("Text Command.")
		n, err = tc.ReadFrom(NewReader(p.Header))
		// n, err = io.ReadFull(r, p.DataR)
		n, err = io.ReadAtLeast(r, p.DataR, p.Header.DataSegLen)
		p.Decode()
		p.textResponce(tc)
	case OpCodeSCSICommand:
		PrintDeb("SCSI Command.")
		n, err = sc.ReadFrom(NewReader(p.Header))
		//n, err = io.ReadFull(r, p.DataR)
		n, err = io.ReadAtLeast(r, p.DataR, p.Header.DataSegLen)
		// DecodeData(p.DataR, p.DS)
		p.SCSICommandResp(sc)
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

	ROpCode.Value = []byte{OpCodeLoginResp, TransitToNextLoginStage | OpCodeNSG | OpCodeCSG}
	p.Set(ROpCode)

	p.Set(RVersionMax)
	p.Set(RVersionActive)

	RTotalAHSLenght.Value = []byte{0x00}
	p.Set(RTotalAHSLenght)

	RDataSegmentLength.Value = dataSegmentLength
	p.Set(RDataSegmentLength)

	RISID.Value = lh.ISID[:]
	p.Set(RISID)

	RTSIH.Value = []byte{0x01, 0x00}
	p.Set(RTSIH)

	RInitiatorTaskTag.Value = []byte{0x00, 0x00, 0x00, 0x00}
	p.Set(RInitiatorTaskTag)

	RStatSN.Value = []byte{0x00, 0x00, 0x00, 0x00}
	p.Set(RStatSN)

	RExpCmdSN.Value = []byte{0x00, 0x00, 0x00, 0x01}
	p.Set(RExpCmdSN)

	RMaxCmdSN.Value = []byte{0x00, 0x00, 0x00, 0x02}
	p.Set(RMaxCmdSN)

	RStatusClass.Value = []byte{0x00}
	p.Set(RStatusClass)

	RStatusDetail.Value = []byte{0x00}
	p.Set(RStatusDetail)

	RDataSegment.Value = dataSegment
	p.Set(RDataSegment)

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
	RDataSegmentLength.Value = []byte(dataSegmentLength)
	p.DataW = make([]byte, 48 + len(dataSegment))

	ROpCode.Value =  []byte{OpCodeTextResp}
	p.Set(ROpCode)
	p.Set(TCFlags)
	p.Set(RTotalAHSLenght)
	p.Set(RDataSegmentLength)
	p.Set(TCLUN)
	RInitiatorTaskTag.Value = tc.InitTaskTag[:]
	p.Set(RInitiatorTaskTag)
	p.Set(TCTargetTransferTag)
	p.Set(TCStatSN)
	p.Set(TCExpCmdSN)
	p.Set(TCMaxCmdSN)
	RDataSegment.Value = dataSegment
	p.Set(RDataSegment)

	return
}

func (p *ISCSIConnection)Decode() {

	arrString := strings.Split(string(p.DataR), string("\x00"))
	for _, element := range arrString {
		if strings.Contains(element, "=") {
			ar := strings.Split(element, "=")
			p.DS[ar[0]] = ar[1]
		}
	}
return
}

// =============== ISCSI Header ===============
type ISCSIHeader struct {
	Raw		[48]byte
	OpCode		byte		// Operation code
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes Data segmetnt length
}

func (h *ISCSIHeader)Read(p []byte) (n int, err error) {
	n = copy(p, h.Raw[:])
	return n, err
}

func (p *ISCSIHeader)ReadFrom(r io.Reader) (int, error) {
	n, err := io.ReadFull(r, p.Raw[:])
	p.OpCode = p.Raw[0] & 0x3f
	p.TotAHSLen	= int(p.Raw[4])
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, p.Raw[5:8]...)))
	return n, err
}

// =============== Login Command ===============
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
}

func (p *LoginHeader)ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 48)
	n, err := io.ReadFull(r, buf)

	p.I		= selectBit((buf[0]), 0x40)
	p.OpCode 	= buf[0] & 0x3f
	p.OpCodeSF	= buf[1]
	p.T		= selectBit(p.OpCodeSF, 0x80)
	p.C		= selectBit(p.OpCodeSF, 0x40)
	p.CSG		= int(selectBits(p.OpCodeSF, 0x0c))
	p.NSG		= int(selectBits(p.OpCodeSF, 0x03))
	p.VerMax	= buf[2]
	p.VerMin	= buf[3]
	p.TotAHSLen	= int(buf[4])
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, buf[5:8]...)))
	_ = copy(p.ISID[:], buf[8:14])
	_ = copy(p.TSIH[:], buf[14:16])
	_ = copy(p.InitTaskTag[:], buf[16:20])
	_ = copy(p.CID[:], buf[20:22])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))

	return n, err
}

// =============== Text Command ===============
type TextHeader struct {
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
}

func (p *TextHeader)ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 48)
	n, err := io.ReadFull(r, buf)

	p.I		= selectBit((buf[0]), 0x40)
	p.OpCode 	= buf[0] & 0x3f
	p.OpCodeSF	= buf[1]
	p.F		= selectBit(p.OpCodeSF, 0x80)
	p.C		= selectBit(p.OpCodeSF, 0x40)
	p.TotAHSLen	= int(buf[4])
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, buf[5:8]...)))
	_ = copy(p.LUN[:], buf[8:16])
	_ = copy(p.InitTaskTag[:], buf[16:20])
	_ = copy(p.TargetTransTag[:], buf[20:24])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))

	return n, err
}
// =============== SCSI Command ===============
type SCSIHeader struct {
	OpCode		byte		// 1 byte
	OpCodeSF	byte		// 1 byte OpCodeSpcField
	I		bool		// Immediate bit
	F		bool		// Final bit
	R		bool		// 1 bit Data will be read from target
	W		bool		// 1 bit Data will be written to target
	ATTR		int		// 3 bits Task Attributes
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes
	LUN		[8]byte		// 8 bytes
	InitTaskTag	[4]byte		// 4 bytes
	ExpDataTransLen	[4]byte		// 4 bytes
	CmdSN		int		// 4 bytes
	ExpStatSN	int		// 4 bytes
	SCSIComDescBlk	[16]byte	// 16 byte SCSI Command Descriptor Block
}

func (p *SCSIHeader)ReadFrom(r io.Reader) (int, error) {
	buf := make([]byte, 48)
	n, err := io.ReadFull(r, buf)

	p.I		= selectBit((buf[0]), 0x40)
	p.OpCode 	= buf[0] & 0x3f
	p.OpCodeSF	= buf[1]
	p.F		= selectBit(p.OpCodeSF, 0x80)
	p.R		= selectBit(p.OpCodeSF, 0x40)
	p.W		= selectBit(p.OpCodeSF, 0x20)
	p.ATTR		= int(selectBits(p.OpCodeSF, 0x07))
	p.TotAHSLen	= int(buf[4])
	p.DataSegLen	= int(binary.BigEndian.Uint32(append([]byte{0}, buf[5:8]...)))
	_ = copy(p.LUN[:], buf[8:16])
	_ = copy(p.InitTaskTag[:], buf[16:20])
	_ = copy(p.ExpDataTransLen[:], buf[20:24])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))
	_ = copy(p.SCSIComDescBlk[:], buf[32:48])

	return n, err
}

func (p *ISCSIConnection) SCSICommandResp(sc SCSIHeader) {
	var dataSegment []byte

	//dataSegmentLength := intToByte(len(dataSegment), 6)
	//RDataSegmentLength.Value = []byte(dataSegmentLength)
	//p.DataW = make([]byte, 48 + len(dataSegment))

	ROpCode.Value =  []byte{FinalTrue || AcknowledgeFalse || ResidualOverflowFalse || ResidualUnOverflowFalse || StatusBitTrue}
	p.Set(ROpCode)
	
	StatusField.Value = []byte{0x00}
	p.Set(StatusField)

	RTotalAHSLenght.Value = []byte{0x00}
	p.Set(RTotalAHSLenght)

	p.Set(RDataSegmentLength)

	p.Set(TCLUN)

	RInitiatorTaskTag.Value = tc.InitTaskTag[:]
	p.Set(RInitiatorTaskTag)

	p.Set(TCTargetTransferTag)

	p.Set(TCStatSN)
	p.Set(TCExpCmdSN)
	p.Set(TCMaxCmdSN)
	RDataSegment.Value = dataSegment
	p.Set(RDataSegment)

	return
}
/*
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
*/
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

func (p SCSIHeader)String() (string) {
	return fmt.Sprintf("OpCode=%x, OpCodeSF=%x, I=%t, F=%t, R=%t, W=%t, ATTR=%d,  TotAHSLen=%d, DataSegLen=%d, LUN=%x, InitTaskTag=%x, ExpDataTransLen=%x, CmdSN=%d, ExpStatSN=%d, SCSIComDescBlk=%x",
		p.OpCode, p.OpCodeSF, p.I, p.F, p.R, p.W, p.ATTR, p.TotAHSLen, p.DataSegLen, p.LUN, p.InitTaskTag, p.ExpDataTransLen, p.CmdSN, p.ExpStatSN, p.SCSIComDescBlk)
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

