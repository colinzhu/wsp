package client

import (
	"encoding/binary"
	"io"
	"net"

	"github.com/gowsp/wsp/pkg/logger"
	"github.com/miekg/dns"
)

func handleUDPAssociate(tcpConn net.Conn) {
	// Start a UDP server on a random port
	udpServer, err := net.ListenUDP("udp", &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: 0, // Let the system choose a free port
	})
	if err != nil {
		logger.Error("listen socks5 UDP error %s", err)
		return
	}
	defer udpServer.Close()

	// prepare the UDP associate response with the UDP server address and port number
	udpServerIP := tcpConn.LocalAddr().(*net.TCPAddr).IP.To4()
	udpServerPort := udpServer.LocalAddr().(*net.UDPAddr).Port
	udpAssociateResp := []byte{0x05, 0x00, 0x00, 0x01}
	udpAssociateResp = append(udpAssociateResp, udpServerIP...)
	udpAssociateResp = append(udpAssociateResp, []byte{byte(udpServerPort >> 8), byte(udpServerPort)}...)

	// send the UDP associate response to the client
	_, err = tcpConn.Write(udpAssociateResp)
	if err != nil {
		logger.Error("failed to send UDP port number: %s", err)
	}
	//logger.Info("%s listening UDP: %s, replied: %d", tcpConn.RemoteAddr(), udpServer.LocalAddr(), udpAssociateResp)

	// Wait and read the UDP request from the client
	buffer := make([]byte, 4096)
	n, udpClientAddr, err := udpServer.ReadFrom(buffer)
	if err != nil {
		logger.Error("Failed to read UDP request: %s", err)
		return
	}
	//logger.Info("%s udpClientAddr: %s, UDP reqeust first 10 bytes: %d", tcpConn.RemoteAddr(), udpClientAddr, buffer[:10])

	// targetDNSServer, packedDNSResult, shouldReturn := getPackedDNSQueryResult(buffer, n)
	// if shouldReturn {
	// 	return
	// }

	// get the DNS request from the client
	targetDNSServer := buffer[4:10]
	dnsQueryObj := new(dns.Msg)
	if err := dnsQueryObj.Unpack(buffer[10:n]); err != nil {
		logger.Error("failed to unpack DNS request: %s", err)
		return
	}
	logger.Info("%s udpClientAddr: %s, DNS server: %d, DNS request: %s", tcpConn.RemoteAddr(), udpClientAddr, targetDNSServer, dnsQueryObj.Question[0].String())

	// prepare the DNS response
	dnsResultObj := new(dns.Msg)
	dnsResultObj.Truncated = true
	dnsResultObj.SetReply(dnsQueryObj)
	packedDNSResult, _ := dnsResultObj.Pack()
	udpRespHeader := []byte{0x00, 0x00, 0x00, 0x01}
	udpRespHeader = append(udpRespHeader, targetDNSServer...)
	combinedResponse := append(udpRespHeader, packedDNSResult...)

	// send the DNS response to the client
	if _, err := udpServer.WriteTo(combinedResponse, udpClientAddr); err != nil {
		logger.Error("failed to send DNS response: %s", err)
		return
	}
	//logger.Info("%s udpClientAddr: %s, DNS server: %d, DNS response truncated=ture sent.", tcpConn.RemoteAddr(), udpClientAddr, targetDNSServer)
}

// this is an implementation of the DNS over TCP protocol
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
