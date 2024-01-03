package client

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"

	"github.com/gowsp/wsp/pkg/logger"
	"github.com/gowsp/wsp/pkg/msg"
	"github.com/miekg/dns"
)

var errVersion = fmt.Errorf("unsupported socks version")

// Socks5Proxy implement DynamicProxy
type Socks5Proxy struct {
	conf *msg.WspConfig
	wspc *Wspc
}

func (p *Socks5Proxy) Listen() {
	address := p.conf.Address()
	logger.Info("listen socks5 on %s", address)
	l, err := net.Listen(p.conf.Network(), address)
	if err != nil {
		logger.Error("listen socks5 error %s", err)
		return
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			logger.Error("accept socks5 error %s", err)
			continue
		}
		//logger.Info("accept socks5 %s", conn.RemoteAddr())
		go func() {
			defer conn.Close()
			err := p.ServeConn(conn)
			if err != nil || err == io.EOF {
				logger.Error("ServeConn error, close socks5 %s", conn.RemoteAddr(), err)
				return
			}
		}()
	}
}

func (p *Socks5Proxy) listenUDP(tcpConn net.Conn) {
	// logger.Info("listen socks5 UDP on %s", ":10812")
	//udpConn, err := net.ListenPacket("udp", ":10812")
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0, // Let the system choose a free port
	})
	if err != nil {
		logger.Error("listen socks5 UDP error %s", err)
		return
	}
	defer udpConn.Close()

	// Get the chosen port number
	udpServerAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := udpServerAddr.Port

	ipAndPort := []byte{0x05, 0x00, 0x00, 0x01, 0xC0, 0xA8, 0x1F, 0x31, byte(port >> 8), byte(port)}
	logger.Info("%s, -> %s proxy UDP connect created: %d", tcpConn.RemoteAddr(), udpConn.LocalAddr(), ipAndPort)

	// Send the port number to the client
	_, err = tcpConn.Write(ipAndPort)
	if err != nil {
		logger.Error("failed to send UDP port number: %s", err)
	}

	buffer := make([]byte, 4096)
	n, udpClientAddr, err := udpConn.ReadFrom(buffer)
	if err != nil {
		logger.Error("accept socks5 UDP error %s", err)
		return
	}
	logger.Info("%s, udpClientAddr: %s, first 10 bytes from UDP request : %d", tcpConn.RemoteAddr(), udpClientAddr, buffer[:10])

	// targetDNSServer, packedDNSResult, shouldReturn := getPackedDNSQueryResult(buffer, n)
	// if shouldReturn {
	// 	return
	// }

	targetDNSServer := buffer[4:10]

	dnsQueryObj := new(dns.Msg)
	if err := dnsQueryObj.Unpack(buffer[10:n]); err != nil {
		logger.Error("failed to unpack DNS request: %s", err)
		return
	}
	logger.Info("%s -> %d, unpacked DNS request: %s", tcpConn.RemoteAddr(), targetDNSServer, dnsQueryObj.String())

	dnsResultObj := new(dns.Msg)
	dnsResultObj.Truncated = true
	dnsResultObj.SetReply(dnsQueryObj)

	packedDNSResult, _ := dnsResultObj.Pack()

	udpRespHeader := []byte{0x00, 0x00, 0x00, 0x01}

	// Append targetDNSServer to udpRespHeader
	udpRespHeader = append(udpRespHeader, targetDNSServer...)

	// Combine the UDP response header and the DNS response
	combinedResponse := append(udpRespHeader, packedDNSResult...)

	if _, err := udpConn.WriteTo(combinedResponse, udpClientAddr); err != nil {
		logger.Error("failed to send DNS response: %s", err)
		return
	}

	// // Create a DNS response with the TC flag set
	// resp := new(dns.Msg)
	// resp.SetReply(msg)
	// resp.Truncated = true
	// logger.Info("Created DNS response with TC flag set")

	// // Pack the DNS response
	// respBytes, err := resp.Pack()
	// if err != nil {
	// 	logger.Error("failed to pack DNS response: %s", err)
	// 	continue
	// }

	// // Send the DNS response
	// if _, err := conn.WriteTo(respBytes, addr); err != nil {
	// 	logger.Error("failed to send DNS response: %s", err)
	// }
	// logger.Info("Successfully packed DNS response: %s", resp.String())

	// go func() {
	// 	logger.Info("Received UDP %s from %s", string(buffer[:n]), addr)
	// 	if err != errVersion {
	// 		logger.Error("serve socks5 error", err)
	// 	}
	// }()
	//}()
	//}
}

func getPackedDNSQueryResult(buffer []byte, n int) ([]byte, []byte, bool) {
	dnsQueryObj := new(dns.Msg)
	if err := dnsQueryObj.Unpack(buffer[10:n]); err != nil {
		logger.Error("failed to unpack DNS request: %s", err)
		return nil, nil, true
	}
	logger.Info("Successfully unpacked DNS request: %s", dnsQueryObj.String())

	proxyTCPConn, err := net.Dial("tcp", "127.0.0.1:10811")
	if err != nil {
		logger.Error("failed to connect to SOCKS5 proxy: %s", err)
		return nil, nil, true
	}
	defer proxyTCPConn.Close()

	proxyTCPConn.Write([]byte{0x05, 0x01, 0x00})

	proxyAuthResp := make([]byte, 2)
	_, err = io.ReadFull(proxyTCPConn, proxyAuthResp)
	if err != nil {
		logger.Error("failed to read proxy auth response: %s", err)
		return nil, nil, true
	}

	proxyTCPConn.Write([]byte{0x05, 0x01, 0x00, 0x01})

	targetDNSServer := buffer[4:10]
	proxyTCPConn.Write(targetDNSServer)

	proxyResp := make([]byte, 10)
	_, err = io.ReadFull(proxyTCPConn, proxyResp)
	if err != nil {
		logger.Error("failed to read proxy response: %s", err)
		return nil, nil, true
	}

	packedQuery, err := dnsQueryObj.Pack()
	if err != nil {
		logger.Error("failed to pack DNS request: %s", err)
		return nil, nil, true
	}

	tcpDNSRqst := make([]byte, 2+len(packedQuery))

	binary.BigEndian.PutUint16(tcpDNSRqst, uint16(len(packedQuery)))

	copy(tcpDNSRqst[2:], packedQuery)

	if _, err := proxyTCPConn.Write(tcpDNSRqst); err != nil {
		logger.Error("failed to send DNS request: %s", err)
		return nil, nil, true
	}

	tcpDNSResponse := make([]byte, 512)
	n, err = io.ReadAtLeast(proxyTCPConn, tcpDNSResponse, 1)
	if err != nil {
		logger.Error("failed to read TCP DNS response: %s", err)
		return nil, nil, true
	}
	tcpDNSResponse = tcpDNSResponse[2:n]

	dnsResultObj := new(dns.Msg)
	if err := dnsResultObj.Unpack(tcpDNSResponse); err != nil {
		logger.Error("failed to unpack DNS response: %s", err)
		return nil, nil, true
	}
	dnsQueryObj.Truncated = true
	logger.Info("Successfully unpacked DNS response: %s", dnsResultObj.String())

	packedDnsResult, err := dnsResultObj.Pack()
	if err != nil {
		logger.Error("failed to pack DNS response: %s", err)
		return nil, nil, true
	}
	return targetDNSServer, packedDnsResult, false
}

func (p *Socks5Proxy) ServeConn(conn net.Conn) error {
	if err := p.auth(conn); err != nil {
		logger.Error("auth socks5 error %s", err)
		conn.Close()
		return err
	}
	//logger.Info("auth passed, socks5 %s", conn.RemoteAddr())
	destAddr, isUDP, err := p.getDestAddrFromRequest(conn)
	if err != nil {
		logger.Error("getDestAddrFromRequest faield, socks5 error %s", err)
		conn.Close()
		return err
	}
	logger.Info("%s to dest addr: %s, isUDP=%t", conn.RemoteAddr(), destAddr, isUDP)
	p.replies(destAddr, isUDP, conn)
	return nil
}

func (p *Socks5Proxy) auth(conn net.Conn) error {
	// +----+----------+----------+
	// |VER | NMETHODS | METHODS  |
	// +----+----------+----------+
	// | 1  |    1     | 1 to 255 |
	// +----+----------+----------+
	info := make([]byte, 2)
	if _, err := io.ReadFull(conn, info); err != nil {
		return err
	}
	if info[0] != 0x05 {
		conn.Write([]byte{0x05, 0xFF})
		return errVersion
	}
	methods := make([]byte, info[1])
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}
	// +----+--------+
	// |VER | METHOD |
	// +----+--------+
	// | 1  |   1    |
	// +----+--------+
	_, err := conn.Write([]byte{0x05, 0x00})
	return err
}

func (p *Socks5Proxy) getDestAddrFromRequest(conn net.Conn) (addr string, isUDP bool, err error) {
	// +----+-----+-------+------+----------+----------+
	// |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
	// +----+-----+-------+------+----------+----------+
	// | 1  |  1  | X'00' |  1   | Variable |    2     |
	// +----+-----+-------+------+----------+----------+
	info := make([]byte, 4)

	if _, err := io.ReadFull(conn, info); err != nil {
		logger.Error("getDestAddrFromRequest, return '', error %s", err)
		return "", false, err
	}
	logger.Info("%s proxy request VER,CMD,RSV,ATYP: %d", conn.RemoteAddr(), info)
	if info[0] != 0x05 {
		return "", false, errVersion
	}
	var host string

	switch info[1] { // Command
	case 0x01: // CONNECT
		switch info[3] { // Address type
		case 1: // IPv4
			host, err = p.readIP(conn, net.IPv4len)
			if err != nil {
				return "", false, err
			}
		case 4: // IPv6
			host, err = p.readIP(conn, net.IPv6len)
			if err != nil {
				return "", false, err
			}
		case 3: // DOMAINNAME
			if _, err := io.ReadFull(conn, info[3:]); err != nil {
				return "", false, err
			}
			hostName := make([]byte, info[3])
			if _, err := io.ReadFull(conn, hostName); err != nil {
				return "", false, err
			}
			host = string(hostName)
		default:
			return "", false, fmt.Errorf("unrecognized address type")
		}
		//logger.Info("host: %s", host)

		if _, err := io.ReadFull(conn, info[2:]); err != nil {
			return "", false, err
		}
		port := binary.BigEndian.Uint16(info[2:])
		//logger.Info("port: %d", port)

		//logger.Info("Command: %d, Address type: %d, Host: %s, Port: %d", info[1], info[3], host, port)

		return net.JoinHostPort(host, fmt.Sprintf("%d", port)), false, nil

	case 0x03: // UDP ASSOCIATE
		// Handle UDP ASSOCIATE here
		// For now, just return an empty address and nil error
		//conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x7F, 0x00, 0x00, 0x01, 0x2A, 0x3C})
		udpHostAndPort := make([]byte, 6)
		if _, err := io.ReadFull(conn, udpHostAndPort); err != nil {
			logger.Error("error read udpHostAndPort, return '', error %s", err)
			return "", false, err
		}
		//logger.Info("udpHostAndPort: %d", udpHostAndPort)

		//ip := net.IP(udpHostAndPort[:4])
		//port := binary.BigEndian.Uint16(udpHostAndPort[4:])
		//logger.Info("udpHostAndPort: %s:%d", ip, port)

		return "", true, nil
	default:
		return "", false, fmt.Errorf("unrecognized command: %d", info)
	}
}

func (p *Socks5Proxy) readIP(conn net.Conn, len byte) (string, error) {
	addr := make([]byte, len)
	if _, err := io.ReadFull(conn, addr); err != nil {
		return "", err
	}
	return net.IP(addr).String(), nil
}
func (p *Socks5Proxy) replies(destAddr string, isUDP bool, localConn net.Conn) {
	if isUDP {
		//logger.Info("%s isUDP=true", localConn.RemoteAddr())
		//localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0xC0, 0xA8, 0x1F, 0x31, 0x2A, 0x3C})
		p.listenUDP(localConn)
		return
	}
	dynamicAddr := p.conf.DynamicAddr(destAddr)
	//logger.Info("dynamicAddr: %s, addr %s", dynamicAddr, destAddr)

	remote, err := p.wspc.wan.DialTCP(localConn, dynamicAddr)
	if err != nil {
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		logger.Error("DialTCP to %s failed, %s", destAddr, err.Error())
		return
	}
	logger.Info("%s -> %s DialTCP succeeded", localConn.RemoteAddr(), destAddr)
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	localConn.Write(resp)
	//logger.Info("responded to the client with %d", resp)

	n, _ := io.Copy(remote, localConn)
	remote.Close()
	logger.Info("%s -> %s connection closed, %d bytes copied.", localConn.RemoteAddr(), destAddr, n)
}
