package iscsilt

import (
	"testing"
	"encoding/base64"
	"io"
	"bytes"
)

type Msg interface{
	WriteTo(w io.Writer) (int, error)
	ReadFrom(r io.Reader) (int, error)
}

type LoginReq struct{
	Op int
}

var cases = []struct{
	msg Msg
	expect string
}{
	{
		LoginReq{Op:1},
		"AQIDBAU=",
	},
	{
		LoginReq{Op:2},
		"AQIDBAA=",
	},
}

func TestEncode(t *testing.T) {
	for i, c := range cases {
		buf := bytes.NewBuffer(nil)
		if _, err := c.msg.WriteTo(buf); err != nil {
			t.Fatalf("case %d: %v",i+1,err)
		} else if c.expect != base64.StdEncoding.EncodeToString(buf.Bytes()) {
			t.Fatalf("case %d: wrong packet data",i+1)
		}
	}
}
