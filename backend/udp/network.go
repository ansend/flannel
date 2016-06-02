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

package udp

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"syscall"

	log "github.com/coreos/flannel/Godeps/_workspace/src/github.com/golang/glog"
	"github.com/coreos/flannel/Godeps/_workspace/src/github.com/vishvananda/netlink"
	"github.com/coreos/flannel/Godeps/_workspace/src/golang.org/x/net/context"

	"github.com/coreos/flannel/backend"
	"github.com/coreos/flannel/pkg/ip"
	"github.com/coreos/flannel/subnet"
)

const (
	encapOverhead = 28 // 20 bytes IP hdr + 8 bytes UDP hdr
)

const (
	sock2tun = 0
	tun2sock = 1
)

type network struct {
	backend.SimpleNetwork
	name   string
	port   int
	ctl    *os.File
	ctl2   *os.File
	tun    *os.File
	tunmq  []*os.File
	conn   *net.UDPConn
	multiq bool
	qnum   int
	tunNet ip.IP4Net
	sm     subnet.Manager
}

func newNetwork(name string, sm subnet.Manager, extIface *backend.ExternalInterface, port int, enableMq bool, nw ip.IP4Net, l *subnet.Lease) (*network, error) {
	n := &network{
		SimpleNetwork: backend.SimpleNetwork{
			SubnetLease: l,
			ExtIface:    extIface,
		},
		name: name,
		port: port,
		sm:   sm,
	}
	surpportMq := false
	// get kernel version , multi-queue tun-tap driver is only support on 3.8 or latter kernel.
	vstring, verr := getKernelVersionString()

	if verr == nil {

		v1, v2, v3, verr := extractKernelVersion(vstring)
		log.Info("kernel version is %d.%d.%d", v1, v2, v3)
		if verr == nil {
			surpportMq = isKernelSupportTunTapMultiQueue(v1, v2)
		}

	}
	// only config enable multi-queue and the linux kernel version support tun-tap multi-queue driver(at leatest 3.8)
	if surpportMq && enableMq {
		n.multiq = true
	} else {
		n.multiq = false
	}

	n.tunNet = nw

	if err := n.initTun(); err != nil {
		return nil, err
	}

	var err error
	n.conn, err = net.ListenUDP("udp4", &net.UDPAddr{IP: extIface.IfaceAddr, Port: port})
	if err != nil {
		return nil, fmt.Errorf("failed to start listening on UDP socket: %v", err)
	}

	n.ctl, n.ctl2, err = newCtlSockets()
	if err != nil {
		return nil, fmt.Errorf("failed to create control socket: %v", err)
	}

	return n, nil
}

func (n *network) Run(ctx context.Context) {
	defer func() {
		n.tun.Close()
		n.conn.Close()
		n.ctl.Close()
		n.ctl2.Close()
	}()

	wg := sync.WaitGroup{}
	defer wg.Wait()

	if n.multiq {
		wg.Add(2)
		log.Info("start routine for multiqueue proxy")
		go func() {
			runCProxyMq(n.tunmq, n.conn, n.ctl2, n.tunNet.IP, n.MTU(), tun2sock)
			wg.Done()
		}()
		go func() {
			runCProxyMq(n.tunmq, n.conn, n.ctl2, n.tunNet.IP, n.MTU(), sock2tun)
			wg.Done()
		}()

	} else {
		wg.Add(1)
		log.Info("start routine for single queue proxy")
		go func() {
			runCProxy(n.tun, n.conn, n.ctl2, n.tunNet.IP, n.MTU())
			wg.Done()
		}()
	}

	log.Info("Watching for new subnet leases")

	evts := make(chan []subnet.Event)

	wg.Add(1)
	go func() {
		subnet.WatchLeases(ctx, n.sm, n.name, n.SubnetLease, evts)
		wg.Done()
	}()

	for {
		select {
		case evtBatch := <-evts:
			n.processSubnetEvents(evtBatch)

		case <-ctx.Done():
			stopProxy(n.ctl)
			return
		}
	}
}

func (n *network) MTU() int {
	return n.ExtIface.Iface.MTU - encapOverhead
}

func newCtlSockets() (*os.File, *os.File, error) {
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, nil, err
	}

	f1 := os.NewFile(uintptr(fds[0]), "ctl")
	f2 := os.NewFile(uintptr(fds[1]), "ctl")
	return f1, f2, nil
}

func (n *network) initTun() error {
	var tunName string
	var err error

	if n.multiq {
		n.qnum = 8 // the qnum should be the the little one of 8 and max CPU core number
		if runtime.NumCPU() < n.qnum {
			n.qnum = runtime.NumCPU()
		}

		n.tunmq, tunName, err = ip.OpenTunMq("flannel%d", n.qnum)

	} else {
		n.tun, tunName, err = ip.OpenTun("flannel%d")
	}

	if err != nil {
		return fmt.Errorf("failed to open TUN device: %v", err)
	}

	err = configureIface(tunName, n.tunNet, n.MTU())
	if err != nil {
		return err
	}

	return nil
}

func configureIface(ifname string, ipn ip.IP4Net, mtu int) error {
	iface, err := netlink.LinkByName(ifname)
	if err != nil {
		return fmt.Errorf("failed to lookup interface %v", ifname)
	}

	err = netlink.AddrAdd(iface, &netlink.Addr{ipn.ToIPNet(), ""})
	if err != nil {
		return fmt.Errorf("failed to add IP address %v to %v: %v", ipn.String(), ifname, err)
	}

	err = netlink.LinkSetMTU(iface, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU for %v: %v", ifname, err)
	}

	err = netlink.LinkSetUp(iface)
	if err != nil {
		return fmt.Errorf("failed to set interface %v to UP state: %v", ifname, err)
	}

	// explicitly add a route since there might be a route for a subnet already
	// installed by Docker and then it won't get auto added
	err = netlink.RouteAdd(&netlink.Route{
		LinkIndex: iface.Attrs().Index,
		Scope:     netlink.SCOPE_UNIVERSE,
		Dst:       ipn.Network().ToIPNet(),
	})
	if err != nil && err != syscall.EEXIST {
		return fmt.Errorf("failed to add route (%v -> %v): %v", ipn.Network().String(), ifname, err)
	}

	return nil
}

func (n *network) processSubnetEvents(batch []subnet.Event) {
	for _, evt := range batch {
		switch evt.Type {
		case subnet.EventAdded:
			log.Info("Subnet added: ", evt.Lease.Subnet)

			setRoute(n.ctl, evt.Lease.Subnet, evt.Lease.Attrs.PublicIP, n.port)

		case subnet.EventRemoved:
			log.Info("Subnet removed: ", evt.Lease.Subnet)

			removeRoute(n.ctl, evt.Lease.Subnet)

		default:
			log.Error("Internal error: unknown event type: ", int(evt.Type))
		}
	}
}

// Runs "uname -r " to get the kernel version string
func getKernelVersionString() (string, error) {
	cmd := exec.Command("uname", "-r")
	var out bytes.Buffer
	cmd.Stdout = &out
	err := cmd.Run()
	if err != nil {
		return "", err
	}
	fmt.Println("kernel version string ", out.String())
	return out.String(), nil
}

// get the kernel version
// e.g. "2.6.32-504.16.2.el6.x86_64" would return (2, 6, 32, nil)
// e.g. "4.2.0-16-generic" would return (4.2.0,nil)
func extractKernelVersion(str string) (int, int, int, error) {
	//versionMatcher := regexp.MustCompile("^([0-9]+)\\.([0-9]+)\\.([0-9]+)")
	versionMatcher := regexp.MustCompile(`^([0-9]+)\.([0-9]+)\.([0-9]+)`)
	result := versionMatcher.FindStringSubmatch(str)
	if result == nil {
		return 0, 0, 0, fmt.Errorf("no iptables version found in string: %s", str)
	}

	v1, err := strconv.Atoi(result[1])
	if err != nil {
		return 0, 0, 0, err
	}

	v2, err := strconv.Atoi(result[2])
	if err != nil {
		return 0, 0, 0, err
	}

	v3, err := strconv.Atoi(result[3])
	if err != nil {
		return 0, 0, 0, err
	}
	fmt.Println("v1 v2 v3 is ", v1, v2, v3)
	return v1, v2, v3, nil
}

func isKernelSupportTunTapMultiQueue(v1 int, v2 int) bool {

	if v1 > 3 {
		return true
	} else if v1 == 3 && v2 >= 8 {
		return true
	}
	return false
}
