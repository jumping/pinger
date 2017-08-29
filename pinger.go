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
)

type Pinger struct {
	sync.Mutex
	closed   bool
	probes   map[string][]chan<- bool
	timeouts map[string]time.Time
	conn     *icmp.PacketConn
}

func (p *Pinger) msgBody(addr string) []byte {
	return []byte(fmt.Sprintf("Rebar DHCP Address Probe %s", addr))
}

// Close closes the Pinger.  It will close any open response channels,
// terminate the main loop and any pinging routines, and close the
// ICMP connection.
func (p *Pinger) Close() {
	p.Lock()
	p.closed = true
	p.conn.Close()
	p.Unlock()
}

// InUse has the Pinger test to see if a system is alive within a specified timeframe.
//
// If the result channel yields true, the remote IP responded to an
// ICMP echo request.  If the result channel yields false, either the
// remote IP failed to respond to the echo requests within the
// specified time frame or we recieved a Destination Unreachable
// packet in response to one of our echo requests.
//
// No matter what the timeout is, InUse will only send up to 3 ICMP
// echoo requests during the first 3 seconds after the InUse function
// is called.
//
// You are not responsible for closing the returned channel, the
// Pinger will close it either after sending an appropriate response
// or if the Pinger is closed.  You must use the two-operand recieve
// operator to distinguish between the channel closing and the address
// not responding.
func (p *Pinger) InUse(addr net.IP, timeout time.Duration) <-chan bool {
	p.Lock()
	defer p.Unlock()
	res := make(chan bool)
	if p.closed {
		close(res)
		return res
	}
	ip := addr.String()
	if probes, ok := p.probes[ip]; ok {
		probes = append(probes, res)
	} else {
		p.probes[ip] = []chan<- bool{res}
		go func() {
			for i := 1; i <= 3; i++ {
				tgtAddr := &net.IPAddr{IP: addr}
				msgBody := p.msgBody(tgtAddr.IP.String())
				msg := icmp.Message{
					Type: ipv4.ICMPTypeEcho,
					Code: 0,
					Body: &icmp.Echo{
						Data: msgBody,
						Seq:  i,
					},
				}
				msgBytes, err := msg.Marshal(nil)
				if err == nil {
					_, err := p.conn.WriteTo(msgBytes, tgtAddr)
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

func (p *Pinger) runTimeouts() ([]chan<- bool, bool) {
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

func (p *Pinger) runMessage(peer net.Addr, pktLen int, buf []byte) ([]chan<- bool, bool) {
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
	case ipv4.ICMPTypeDestinationUnreachable:
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
	case ipv4.ICMPTypeEchoReply:
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

func (p *Pinger) mainLoop() {
	buf := make([]byte, 1500)
	for {
		chansToSend := []chan<- bool{}
		valToSend := false
		err := p.conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		if err != nil && !p.closed {
			p.Close()
		}
		n, peer, err := p.conn.ReadFrom(buf)
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
			p.Lock()
			p.conn.Close()
			p.closed = true
			toClose := []chan<- bool{}
			for _, chList := range p.probes {
				toClose = append(toClose, chList...)
			}
			p.probes = map[string][]chan<- bool{}
			p.timeouts = map[string]time.Time{}
			p.Unlock()
			if len(toClose) > 0 {
				for _, ch := range toClose {
					close(ch)
				}
			}
			return
		}
		for _, ch := range chansToSend {
			ch <- valToSend
			close(ch)
		}
	}
}

// New creates a new Pinger.  It will return an error if we are unable
// to open a priveleged ICMPv4 packet socket or if we are not able to
// set a read timeout on the socket, otherwise it will kick off the
// main loop and return the new Pinger.
func New() (*Pinger, error) {
	res := &Pinger{
		probes:   map[string][]chan<- bool{},
		timeouts: map[string]time.Time{},
	}
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(time.Now().Add(1 * time.Second)); err != nil {
		return nil, err
	}
	res.conn = conn
	go res.mainLoop()
	return res, nil
}
