package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func strToPtr(input string) uintptr {
	return uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(input)))
}

func main() {
	user32 := syscall.NewLazyDLL("user32.dll")
	messageboxw := user32.NewProc("MessageBoxW")

	lpCaption := strToPtr("Yeah, buddy!")
	lpText := strToPtr("Hello from Go!")

	ret, _, _ := messageboxw.Call(0, lpText, lpCaption, 1)
	if ret == 2 {
		fmt.Println("Pressed cancel...")
	}
}
