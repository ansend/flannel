// Copyright 2015 flannel authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ip

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

const (
	tunDevice  = "/dev/net/tun"
	ifnameSize = 16
)

type ifreqFlags struct {
	IfrnName  [ifnameSize]byte
	IfruFlags uint16
}

func ioctl(fd int, request, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request, argp)
	if errno != 0 {
		return fmt.Errorf("ioctl failed with '%s'", errno)
	}
	return nil
}

func fromZeroTerm(s []byte) string {
	return string(bytes.TrimRight(s, "\000"))
}

func OpenTun(name string) (*os.File, string, error) {
	tun, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, "", err
	}

	var ifr ifreqFlags
	copy(ifr.IfrnName[:len(ifr.IfrnName)-1], []byte(name+"\000"))
	ifr.IfruFlags = syscall.IFF_TUN | syscall.IFF_NO_PI

	err = ioctl(int(tun.Fd()), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
	if err != nil {
		return nil, "", err
	}

	ifname := fromZeroTerm(ifr.IfrnName[:ifnameSize])
	return tun, ifname, nil
}

func OpenTunMq(name string, qnum int) ([]*os.File, string, error) {

	fdlist := make([]*os.File, qnum)

	tunsuccess := true
	var tun *os.File
	var err error

	var ifr ifreqFlags
	copy(ifr.IfrnName[:len(ifr.IfrnName)-1], []byte(name+"\000"))
	// still no defination of syscall.IFF_MULTI_QUEUE in go,just use 0x0100 here.
	ifr.IfruFlags = syscall.IFF_TUN | syscall.IFF_NO_PI | 0x0100

	for i := 0; i < qnum; i++ {
		tun, err = os.OpenFile(tunDevice, os.O_RDWR, 0)

		if err != nil {
			tunsuccess = false
			break
		}

		err = ioctl(int(tun.Fd()), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr)))
		if err != nil {
			tunsuccess = false
			break
		}

		fdlist[i] = tun

	}

	if !tunsuccess {
		for i := 0; i < qnum; i++ {
			if fdlist[i] != nil {
				(*os.File)(fdlist[i]).Close()
			}
			fdlist[i] = nil
		}
		return fdlist, "", err
	}

	ifname := fromZeroTerm(ifr.IfrnName[:ifnameSize])

	return fdlist, ifname, nil

}
