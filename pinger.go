// Pinger implements a utility object for testing whether a remote
// system is alive based on whether it can respond to ICMP echo
// requests or not.  It currently only handles IPv4.
package pinger

import (
	"bytes"
	"fmt"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// Pinger tests to see if a system or service is alive and responding
// to requests according to whatever metric makes the most sense for
// the system or service.
type Pinger interface {
	// Close closes the Pinger, cancelling any outstanding InUse calls.
	Close()
	// InUse has the Pinger test to see if a system is alive within a
	// specified timeframe.
	//
	// If the result channel yields true, the remote system or service
	// responded to the request within the appropriate timeframe.  If
	// the result channel yields false, either the remote system or
	// service failed to respond within the specified time frame or we
	// recieve positive confirmation that the system or service is not
	// able to answer requests.
	//
	// You are not responsible for closing the returned channel, the
	// Pinger will close it either after sending an appropriate response
	// or if the Pinger is closed.  You must use the two-operand recieve
	// operator to distinguish between the channel closing and the
	// systrem or service not responding.
	InUse(string, time.Duration) <-chan bool
}

type pinger struct {
	*sync.Mutex
	closed       bool
	probes       map[string][]chan<- bool
	timeouts     map[string]time.Time
	conn4, conn6 *icmp.PacketConn
}

func (p *pinger) msgBody(addr string) []byte {
	return []byte(fmt.Sprintf("Rebar DHCP Address Probe %s", addr))
}

func (p *pinger) Close() {
	p.Lock()
	p.closed = true
	for _, probe := range p.probes {
		for _, c := range probe {
			close(c)
		}
	}
	p.probes = nil
	p.timeouts = nil
	p.Unlock()
}

func (p *pinger) InUse(ip string, timeout time.Duration) <-chan bool {
	p.Lock()
	defer p.Unlock()
	res := make(chan bool)
	if p.closed {
		close(res)
		return res
	}
	addr := net.ParseIP(ip)
	if probes, ok := p.probes[ip]; ok {
		probes = append(probes, res)
	} else {
		p.probes[ip] = []chan<- bool{res}
		go func() {
			for i := 1; i <= 3; i++ {
				tgtAddr := &net.IPAddr{IP: addr}
				msgBody := p.msgBody(tgtAddr.IP.String())
				msg := icmp.Message{
					Code: 0,
					Body: &icmp.Echo{
						Data: msgBody,
						Seq:  i,
					},
				}
				if addr.To4() != nil {
					msg.Type = ipv4.ICMPTypeEcho
				}else{
					msg.Type = ipv6.ICMPTypeEchoRequest
				}

				msgBytes, err := msg.Marshal(nil)
				if err == nil {
					if msg.Type == ipv4.ICMPTypeEcho {
						_, err = p.conn4.WriteTo(msgBytes, tgtAddr)
					} else {
						_, err = p.conn6.WriteTo(msgBytes, tgtAddr)
					}
					if err != nil && !err.(net.Error).Temporary() {
						return
					}
				}
				time.Sleep(1 * time.Second)
			}
		}()
	}
	p.timeouts[ip] = time.Now().Add(timeout)
	return res
}

func (p *pinger) runTimeouts() ([]chan<- bool, bool) {
	p.Lock()
	defer p.Unlock()
	res := []chan<- bool{}
	cTime := time.Now()
	toKill := []string{}
	for k, v := range p.timeouts {
		if cTime.After(v) {
			toKill = append(toKill, k)
		}
	}
	if len(toKill) > 0 {
		for _, v := range toKill {
			delete(p.timeouts, v)
			res = append(res, p.probes[v]...)
			delete(p.probes, v)
		}
	}
	return res, false
}

func (p *pinger) runMessage(peer net.Addr, pktLen int, buf []byte) ([]chan<- bool, bool) {
	res := []chan<- bool{}
	retVal := false
	toKill := ""
	var resp *icmp.Message
	resp, err := icmp.ParseMessage(1, buf[:pktLen])
	if err != nil {
		return res, false
	}
	// No read error, so see what kind of ICMP packet we recieved.
	tgtAddr := peer.String()
	p.Lock()
	defer p.Unlock()
	switch resp.Type {
	case ipv4.ICMPTypeDestinationUnreachable, ipv6.ICMPTypeDestinationUnreachable:
		// DestinationUnreachable will not come from our target, so we
		// have to test its body against all our potential targets.
		body, ok := resp.Body.(*icmp.DstUnreach)
		if ok {
			for k := range p.probes {
				msgBody := p.msgBody(k)
				if bytes.Contains(body.Data, msgBody) {
					res = p.probes[k]
					toKill = k
					break
				}
			}
		}
	case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
		_, ok := p.probes[tgtAddr]
		if ok {
			res = p.probes[tgtAddr]
			toKill = tgtAddr
			retVal = true
		}
	}
	if toKill != "" {
		delete(p.timeouts, toKill)
		delete(p.probes, toKill)
	}
	return res, retVal
}

func (p *pinger) mainLoop(conn *icmp.PacketConn) {
	buf := make([]byte, 1500)
	for {
		p.Lock()
		if p.closed {
			conn.Close()
			p.Unlock()
			return
		}
		p.Unlock()
		err := conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err != nil {
			conn.Close()
			p.Close()
			return
		}
		chansToSend := []chan<- bool{}
		valToSend := false
		n, peer, err := conn.ReadFrom(buf)
		if err == nil {
			// We recieved a message.  Process it.
			chansToSend, valToSend = p.runMessage(peer, n, buf)
		} else if err.(net.Error).Timeout() {
			// Our read timed out.  Process the appropriate timeouts
			chansToSend, valToSend = p.runTimeouts()
		} else if err.(net.Error).Temporary() {
			// Transient error, sleep a bit and try again.
			time.Sleep(1 * time.Second)
			continue
		} else {
			// Permanent error, we are done here
			p.Close()
			continue
		}
		for _, ch := range chansToSend {
			ch <- valToSend
			close(ch)
		}
	}
}

// ICMP creates a new Pinger that tests system aliveness via ICMPv4 or
// ICMPv6.  It will return an error if we are unable to open a
// privileged ICMP packet sockets or if we are not able to set a read
// timeout on the sockets.
//
// The InUse method on the Pinter returned by ICMP accepts raw IPv4 or
// IPv6 addresses.
func ICMP() (Pinger, error) {
	res := &pinger{
		Mutex:    &sync.Mutex{},
		probes:   map[string][]chan<- bool{},
		timeouts: map[string]time.Time{},
	}
	conn4, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	if err := conn4.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, err
	}
	res.conn4 = conn4
	go res.mainLoop(conn4)
	conn6, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, err
	}
	if err := conn6.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, err
	}
	res.conn6 = conn6
	go res.mainLoop(conn6)
	return res, nil
}

type fake bool

func (f fake) Close() {}
func (f fake) InUse(string, time.Duration) <-chan bool {
	res := make(chan bool)
	go func() {
		res <- bool(f)
		close(res)
	}()
	return res
}

// Fake returns a Pinger that always returns whatever is passed in for
// ret.  It is intended for use in unit tests.
func Fake(ret bool) Pinger {
	return fake(ret)

}
