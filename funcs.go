package iscsilt

// interface version

import (
	"fmt"
	"runtime"
	"strings"
	"strconv"
)

func aligInt(v int) int {
	i := 4 - (v % 4)
	if i == 4 {
		i = 0
	}
	return v + i
}

func aligByte(s string, c int) []byte {
	l := len(s)
	if l >= c {
		return []byte(s[:c])
	} else {
		ar := make([]byte, c-l)
		PrintDeb(ar, len(ar), s)
		return append(ar, []byte(s)...)
	}
}

func aligString(v string) (r []byte) {
	b := []byte(v)
	r = make([]byte, aligInt(len(b)))
	copy(r, v)
	return r
}

// the function for debugging,
// it print function name, number of string and specified of variables
func PrintDeb(s ...interface{}) {
	name, line := procName(false, 2)
	fmt.Print("=> ", name, " ", line, ": ")
	fmt.Println(s...)
	return
}

// the function return the name of working function
func procName(shortName bool, level int) (name string, line int) {
	pc, _, line, _ := runtime.Caller(level)
	name = runtime.FuncForPC(pc).Name()
	if shortName {
		name = name[strings.Index(name, ".")+1:]
	}
	return name, line
}

// the function convert integer to byte array
func intToByte(v, l int) (out []byte) {
	const (
		space	= string(0x20)
		nul	= string(0x00)
	)
	tabl := map[string]int{	" ": 0, "0": 0, "1": 1, "2": 2, "3": 3, "4": 4,
		"5": 5, "6": 6, "7": 7, "8": 8, "9": 9, "a": 0x0a,
		"b": 0x0b, "c": 0x0c, "d": 0x0d,"e": 0x0e, "f": 0x0f}
	if l%2 != 0 {
		l++
	}
	s := fmt.Sprintf("%"+strconv.Itoa(l)+"x", v)
	s = strings.Replace(s, space, nul, -1)
	out = make([]byte, l/2)

	for k := 1; k <= l-1; k += 2 {
		out[(k-1)/2] = byte(tabl[string(s[k-1])]<<4 + tabl[string(s[k])])
	}
	return out
}