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
	//defer udpConn.Close()

	// Get the chosen port number
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)
	port := localAddr.Port

	ipAndPort := []byte{0x05, 0x00, 0x00, 0x01, 0xC0, 0xA8, 0x1F, 0x31, byte(port >> 8), byte(port)}
	logger.Info("listen socks5 UDP on %d", ipAndPort)

	// Send the port number to the client
	_, err = tcpConn.Write(ipAndPort)
	if err != nil {
		logger.Error("failed to send UDP port number: %s", err)
	}

	//for {
	buffer := make([]byte, 4096)
	n, udpClientAddr, err := udpConn.ReadFrom(buffer)
	if err != nil {
		logger.Error("accept socks5 UDP error %s", err)
		return
	}
	logger.Info("ListenUDP, udpClientAddr: %s, read first 10 bytes : %d", udpClientAddr, buffer[:10])

	//go func() {
	// Parse the DNS request
	dnsQueryObj := new(dns.Msg)
	if err := dnsQueryObj.Unpack(buffer[10:n]); err != nil {
		logger.Error("failed to unpack DNS request: %s", err)
		return
	}
	logger.Info("Successfully unpacked DNS request: %s", dnsQueryObj.String())

	// Create a TCP connection to the local SOCKS5 proxyTCPConn
	proxyTCPConn, err := net.Dial("tcp", "127.0.0.1:10811")
	if err != nil {
		logger.Error("failed to connect to SOCKS5 proxy: %s", err)
		return
	}
	defer proxyTCPConn.Close()

	// Send the DNS request over the TCP connection
	proxyTCPConn.Write([]byte{0x05, 0x01, 0x00})

	// Read the proxy auth response from the TCP connection
	proxyAuthResp := make([]byte, 2)
	_, err = io.ReadFull(proxyTCPConn, proxyAuthResp)
	if err != nil {
		logger.Error("failed to read proxy auth response: %s", err)
		return
	}
	//logger.Info("Successfully read proxy auth response: %d", proxyAuthResp)

	// Send a sock5 CONNECT request to SOCKS 5 server which connects to
	proxyTCPConn.Write([]byte{0x05, 0x01, 0x00, 0x01})
	//logger.Info("original udp server and port %d", buffer[4:10])
	targetDNSServer := buffer[4:10]
	proxyTCPConn.Write(targetDNSServer) // server and port from the original UDP request

	// Read the proxy response from the TCP connection
	proxyResp := make([]byte, 10)
	_, err = io.ReadFull(proxyTCPConn, proxyResp)
	if err != nil {
		logger.Error("failed to read proxy response: %s", err)
		return
	}
	//logger.Info("Successfully read proxy response: %d", proxyResp)

	// Pack the DNS query into a byte slice
	packedQuery, err := dnsQueryObj.Pack()
	if err != nil {
		logger.Error("failed to pack DNS request: %s", err)
		return
	}

	// Create a byte slice to hold the length prefix and the packed query
	tcpDNSRqst := make([]byte, 2+len(packedQuery))
	// Set the length prefix
	binary.BigEndian.PutUint16(tcpDNSRqst, uint16(len(packedQuery)))
	// Copy the packed query after the length prefix
	copy(tcpDNSRqst[2:], packedQuery)

	// dummy tcpDNSRqst
	//tcpDNSRqst := []byte{0x00, 0x38, 0x57, 0xFD, 0x01, 0x20, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x77, 0x77, 0x77, 0x07, 0x74, 0x65, 0x6E, 0x63, 0x65, 0x6E, 0x74, 0x03, 0x63, 0x6F, 0x6D, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x0A, 0x00, 0x08, 0xBF, 0x24, 0x14, 0x85, 0x56, 0x0F, 0x4C, 0x14}
	//logger.Info("tcpDNSRqst, size: %d, %s, %d", len(tcpDNSRqst), tcpDNSRqst, tcpDNSRqst)

	if _, err := proxyTCPConn.Write(tcpDNSRqst); err != nil {
		logger.Error("failed to send DNS request: %s", err)
		return
	}

	// Read the DNS response from the TCP connection
	tcpDNSResponse := make([]byte, 512)
	n, err = io.ReadAtLeast(proxyTCPConn, tcpDNSResponse, 1)
	if err != nil {
		logger.Error("failed to read TCP DNS response: %s", err)
		return
	}
	tcpDNSResponse = tcpDNSResponse[2:n] // first 2 bytes are length field, trim the slice to the actual size of the response
	//logger.Info("Successfully read TCP DNS response: %d, %s", tcpDNSResponse, string(tcpDNSResponse))

	// Parse the DNS dnsResultObj
	dnsResultObj := new(dns.Msg)
	if err := dnsResultObj.Unpack(tcpDNSResponse); err != nil {
		logger.Error("failed to unpack DNS response: %s", err)
		return
	}
	dnsQueryObj.Truncated = true
	logger.Info("Successfully unpacked DNS response: %s", dnsResultObj.String())

	// Send the DNS response back to the UDP client
	packedResponse, err := dnsResultObj.Pack()
	if err != nil {
		logger.Error("failed to pack DNS response: %s", err)
		return
	}

	udpRespHeader := []byte{0x00, 0x00, 0x00, 0x01}

	// Append targetDNSServer to udpRespHeader
	udpRespHeader = append(udpRespHeader, targetDNSServer...)

	// Combine the UDP response header and the DNS response
	combinedResponse := append(udpRespHeader, packedResponse...)

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
	logger.Info("ServeConn getDestAddrFromRequest: %s", destAddr)
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
	logger.Info("getDestAddrFromRequest ReadFull, four bytes : %d", info)
	if info[0] != 0x05 {
		return "", false, errVersion
	}
	var host string

	switch info[1] { // Command
	case 0x01: // CONNECT
		if info[1] == 0x05 {
			logger.Info("getDestAddrFromRequest, COMMAND: 5")
		}
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

		logger.Info("Command: %d, Address type: %d, Host: %s, Port: %d", info[1], info[3], host, port)

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
		ip := net.IP(udpHostAndPort[:4])
		port := binary.BigEndian.Uint16(udpHostAndPort[4:])

		logger.Info("udpHostAndPort: %s:%d", ip, port)

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
		logger.Info("replies: isUDP=true, %s", destAddr)
		//localConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0xC0, 0xA8, 0x1F, 0x31, 0x2A, 0x3C})
		p.listenUDP(localConn)
		return
	}
	dynamicAddr := p.conf.DynamicAddr(destAddr)
	logger.Info("dynamicAddr: %s, addr %s", dynamicAddr, destAddr)

	remote, err := p.wspc.wan.DialTCP(localConn, dynamicAddr)
	if err != nil {
		localConn.Write([]byte{0x05, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		logger.Error("DialTCP to %s failed, %s", destAddr, err.Error())
		return
	}
	logger.Info("DialTCP to %s succeeded", destAddr)
	resp := []byte{0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	localConn.Write(resp)
	//logger.Info("responded to the client with %d", resp)

	// dnsRqst := make([]byte, 58)
	// if _, err := io.ReadFull(localConn, dnsRqst); err != nil {
	// 	logger.Error("error read udpHostAndPort, return '', error %s", err)
	// }
	// logger.Info("dnsRqst: %d", dnsRqst)
	// logger.Info("dnsRqst: %s", string(dnsRqst))

	n, _ := io.Copy(remote, localConn)
	logger.Info("io.Copy from localConn to remote, %d bytes", n)
	remote.Close()
	logger.Info("remote connection closed, dest: %s, local: %s", destAddr, localConn.RemoteAddr())
}
