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
)

const (
	LenPacket 		= 2048 //   1048510
)

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
	TotAHSLen	int		// 1 byte
	DataSegLen	int		// 3 bytes
	ISID		[6]byte		// 6 bytes
	TSIH		[2]byte		// 2 bytes
	InitTaskTag	[4]byte		// 4 bytes
	CID		[2]byte		// 2 bytes
	Res1		[2]byte		// 2 bytes
	CmdSN		int		// 4 bytes
	ExpStatSN	int		// 4 bytes
	Res2		[16]byte	// 16 bytes
	DataW		[]byte		//
	msg		Msg
}

var _ Msg = (*LoginHeader)(nil)

type ISCSIConnection struct {
	LH	LoginHeader
	DS	map[string]string	// Login parameters
	DataR	[]byte			// Data read from ...
	DataW	[]byte			// Data write to ...
}

type Msg interface {
	ReadFrom(io.Reader) (int, error)
	WriteTo(io.Writer) (int, error)
	//	Close(io.ReadWriteCloser) (error)
}

func session(tcpConn *net.TCPConn) bool {
	var h ISCSIConnection

	n, err := h.ReadFrom(tcpConn)
	fmt.Println("65 - n=", n, "\n65 - err=", err) // , "\n65 - h=", h)

	return true
}

func (p *LoginHeader) ReadFrom(r io.Reader) (int, error) {
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
	_ = copy(p.Res1[:], buf[22:24])
	_ = copy(p.Res2[:], buf[32:])
	p.CmdSN		= int(binary.BigEndian.Uint32(buf[24:28]))
	p.ExpStatSN	= int(binary.BigEndian.Uint32(buf[28:32]))
	//p.Res2		= buf[32:]
	return n, err
}

func (p *ISCSIConnection)ReadFrom(r io.Reader) (int, error) {

	n, err := p.LH.ReadFrom(r)

	buf := make([]byte, p.LH.DataSegLen)
	n, err = io.ReadFull(r, buf)

	p.Decode(buf)


	return n, err
}

func (p *ISCSIConnection) Decode(d []byte) error {
	p.DS = make(map[string]string, 0)
	arrString := strings.Split(string(d), string("\x00"))
	for _, element := range arrString {
		if strings.Contains(element, "=") {
			ar := strings.Split(element, "=")
			p.DS[ar[0]] = ar[1]
		}
	}
	return nil
}

func selectBit(bi, bc byte) (bool) {
	return (bi & bc) == bc
}

func selectBits(bi, bc byte) (byte) {
	return (bi & bc)
}

func (p LoginHeader)String() (string) {
	return fmt.Sprintf("p.OpCode=%x, p.OpCodeSF=%x, p.I=%t, p.T=%t, p.C=%t, p.CSG=%d, p.NSG=%d, p.VerMax=%x, p.VerMin=%x, p.TotAHSLen=%d,"+
	" p.DataSegLen=%d, p.ISID=%x, p.TSIH=%x, p.InitTaskTag=%x, p.CID=%x, p.Res1=%x, p.CmdSN=%d,"+
	" p.ExpStatSN=%d, p.Res2=%x",
		p.OpCode, p.OpCodeSF, p.I, p.T, p.C, p.CSG, p.NSG, p.VerMax, p.VerMin, p.TotAHSLen,
		p.DataSegLen, p.ISID, p.TSIH, p.InitTaskTag, p.CID, p.Res1, p.CmdSN,
		p.ExpStatSN, p.Res2)
}

func (p ISCSIConnection)String() (string) {
	out := ""
	for i, j := range p.DS {
		out += " " + fmt.Sprint(i) + "=" + fmt.Sprint(j)
	}
	return fmt.Sprintf("LoginHeader=%s, \nParam=%s", p.LH, out)
}

func (p *ISCSIConnection)WriteTo(w io.Writer) (int, error) {
	p.MakePacket()
	n, err := w.Write(p.DataW)
	return n, err
}

func (p *LoginHeader)WriteTo(w io.Writer) (int, error) {
	n, err := w.Write(p.DataW)
	return n, err
}

func (p *ISCSIConnection)MakePacket() {
	p.DataW = []byte{0x43, 0x87, 0x00, 0x00, 0x00, 0x00, 0x00, 0xf7,
		0x00, 0x02, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	return
}


