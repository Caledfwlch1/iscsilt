package main

import (
	"fmt"
	"runtime"
	"strings"
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
		return append(ar, []byte(s)...)
	}
}
// tttaaa
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