package main

import (
	"container/list"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const (
	tlsRecordChangeCipherSpec = 0x14
	tlsRecordAlert            = 0x15
	tlsRecordHandshake        = 0x16
	tlsRecordApplication      = 0x17
	tlsRecordHeartbeat        = 0x18

	tlsRecordHandshakeClientHello = 0x01
	tlsRecordHandshakeServerHello = 0x02
	tlsRecordTLS10                = 0x0301
	tlsRecordTLS11                = 0x0302
	tlsRecordTLS12                = 0x0303
)

var (
	pcapFile string = "HUM+miaohao+20230408_shihuo_search_7.17.1_Android12@1705.pcap"
	handle   *pcap.Handle
	err      error
	http_num int = 0
	tls_num  int = 0
	dns_num  int = 0

	tlsServerNames     map[string]int
	httpHosts          map[string]int
	dnsQuestionDomains map[string]int
)

func translateCipher(cipher uint16) string {
	if Ciphers[cipher] != "" {
		return Ciphers[cipher]
	}
	return fmt.Sprintf("[UNKNOWN CIPHER 0x%04X]", cipher)
}

func translateTLSVersions(tlsversion uint16) string {
	if TLSVersions[tlsversion] != "" {
		return TLSVersions[tlsversion]
	}
	return fmt.Sprintf("[UNKNOWN TLS VERSION 0x%04X]", tlsversion)
}

func translateAlert(alert uint16) string {
	if Alerts[alert] != "" {
		return Alerts[alert]
	}
	return fmt.Sprintf("[UNKNOWN ALERT 0x%04X]", alert)
}

func printPacketInfo(packet gopacket.Packet) {
	// Let's see if the packet is an ethernet packet
	ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)

		//fmt.Println(reflect.TypeOf(ethernetPacket.EthernetType))
		if ethernetPacket.EthernetType.String() == "IPv4" {
			ipLayer := packet.Layer(layers.LayerTypeIPv4)
			if ipLayer != nil {
				ip, _ := ipLayer.(*layers.IPv4)

				// IP layer variables:
				// Version (Either 4 or 6)
				// IHL (IP Header Length in 32-bit words)
				// TOS, Length, Id, Flags, FragOffset, TTL, Protocol (TCP?),
				// Checksum, SrcIP, DstIP
				switch ip.Protocol {
				// 6 ： TCP
				case 6:
					tcpLayer := packet.Layer(layers.LayerTypeTCP)
					if tcpLayer != nil {
						tcp, _ := tcpLayer.(*layers.TCP)
						if tcp.SrcPort == 80 || tcp.DstPort == 80 { //认为80端口是HTTP
							// TCP layer variables:
							// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
							// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
							applicationLayer := packet.ApplicationLayer()
							if applicationLayer != nil {
								//排除没有应用层

								payload := string(applicationLayer.Payload())
								if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") {
									//有很多applicationLayer!= nil 但没有get/post
									fmt.Println("--------------------------------------------------------------------")
									fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
									fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
									// Ethernet type is typically IPv4 but could be ARP or other
									fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
									fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
									//fmt.Println("Protocol: ", ip.Protocol)
									fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
									fmt.Println("Sequence number: ", tcp.Seq)
									fmt.Println("Protocol: HTTP")
									http_num++

									reg := regexp.MustCompile(`(?s)(GET|POST) (.*?) HTTP.*Host: (.*?)\n`)
									reg_UA := regexp.MustCompile(`(?m)User-Agent: (.*?)\r\n`)
									reg_Content := regexp.MustCompile(`(?s)Content-Type: (.*?)\n`)
									if reg == nil || reg_UA == nil || reg_Content == nil {
										fmt.Println("MustCompile err")
										return
									}
									//提取关键信息
									result := reg.FindStringSubmatch(payload)
									UA := reg_UA.FindStringSubmatch(payload)
									ContentType := reg_Content.FindStringSubmatch(payload)
									if len(result) == 4 {
										strings.TrimSpace(result[2])
										url := "http://" + strings.TrimSpace(result[3]) + strings.TrimSpace(result[2])
										fmt.Println("url:", url)
										fmt.Println("host:", result[3])
										httpHosts[result[3]]++
									} else {
										fmt.Println("error===================")
									}
									if len(UA) != 0 {
										fmt.Println("User-Agent:", UA[1])
									}
									if len(ContentType) != 0 {
										fmt.Println("Content-Type:", ContentType[1])
									}
								}
							}
						}
						if tcp.SrcPort == 443 || tcp.DstPort == 443 {

							/*
								//gopackage官方不能解析TLS，只能解析TLS消息类别（ChangeCipherSpec 、Handshake、AppData、Alert）record层头部（ContentType、TLSversion、length）
								//https://pkg.go.dev/github.com/google/gopacket/layers#TLS
								tlsLayer := packet.Layer(layers.LayerTypeTLS)
								if tlsLayer != nil {
									tls, _ := tlsLayer.(*layers.TLS)
									str3 := tls.DecodeFromBytes()
									fmt.Println(tls.ChangeCipherSpec)
									fmt.Println(tls.Handshake)
								}
							*/
							payload := tcp.BaseLayer.Payload
							// Payload must be bigger than 5 bytes (TLS header is 5 bytes)
							if len(payload) >= 5 {

								if payload[0] == tlsRecordChangeCipherSpec || payload[0] == tlsRecordAlert || payload[0] == tlsRecordHandshake ||
									payload[0] == tlsRecordApplication || payload[0] == tlsRecordHeartbeat {
									fmt.Println("--------------------------------------------------------------------")
									fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
									fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
									// Ethernet type is typically IPv4 but could be ARP or other
									fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
									fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
									//fmt.Println("Protocol: ", ip.Protocol)
									fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
									fmt.Println("Sequence number: ", tcp.Seq)

									tls_num++
									switch payload[0] {
									case tlsRecordChangeCipherSpec:
										fmt.Println("Protocol: tlsChangeCipherSpec")
									case tlsRecordAlert:
										fmt.Println("Protocol: tlsAlert")
									case tlsRecordHandshake:
										fmt.Println("Protocol: tlsHandshake")
									case tlsRecordApplication:
										fmt.Println("Protocol: tlsApplication")
									case tlsRecordHeartbeat:
										fmt.Println("Protocol: tlsHeartbeat")
									}

								}

								// Make sure we have a TLS record here.
								if payload[0] == tlsRecordHandshake {
									// 是tlsRecordHandshake 、等等20个

									// See if message type in handshake layer is TLSRecordHandshakeClientHello
									TLSRecordHandshakeMessageType := payload[5]

									/*
									* If TLS handshake HELLO is CLIENT_HELLO
									 */
									if TLSRecordHandshakeMessageType == tlsRecordHandshakeClientHello {
										// TLS version in Handshake layer
										TLSHandshakeLayerVersion := binary.BigEndian.Uint16(payload[9:11]) // Catch two bytes and interpret as single number (0xXXXX)
										fmt.Println("TLS Version", translateTLSVersions(TLSHandshakeLayerVersion))
										/*
										* Get ciphers
										 */
										// After payload byte 43 there is session ID length and session ID
										// In most cases session ID length is 0x00, so there is no session ID byte.
										// Check the length of the session ID and contunie from there
										// After the session ID length and session ID bytes, the cipher part starts
										// Anatomy of th CLIENT_HELLO handshake message:
										// 	<TLS VERSION 2B> | <RANDOM 32B> | <SESS ID LENGTH 1B> | <SESS ID 0..nB> | <CIPHER SUITES LEN 2B> | <CIPHER 1 2B> | CIPHER 2 2B> | ...
										//  <compression method length 1B> | <compression method 0..nB> | <extension length 2B> |
										//    设第一个extension是sni <extension:Server Name <type 2B> <length 2B> <SNI <LIST LENGTH 2B> <TYPE 1B> <Server Name length 2B> <Server Name 0..nB> > >
										// Detect cipher block start byte
										sessionIDLength := payload[43]
										cipherSuitesStart := 43 + 1 + sessionIDLength // session length offset (43B) + length byte (1B) + sessionIDLength

										// Detect length of cipher part
										CiphersLengthBytes := binary.BigEndian.Uint16(payload[cipherSuitesStart : cipherSuitesStart+2])

										// Walk through all ciphers and count occurances
										ciphersClientsList := list.New()
										var i uint16
										for i = 0; i < CiphersLengthBytes; i += 2 {
											cipherpos := cipherSuitesStart + 2 + byte(i)
											cipher := binary.BigEndian.Uint16(payload[cipherpos : cipherpos+2])
											ciphersClientsList.PushBack(translateCipher(cipher)) // 存储到ciphersClientsList
										}
										fmt.Println("Clients Ciphers-Suites:")
										for i := ciphersClientsList.Front(); i != nil; i = i.Next() {
											fmt.Println(i.Value)
										}
										CompressionMethodStart := uint16(cipherSuitesStart) + CiphersLengthBytes + 2
										CompressionMethodLength := payload[CompressionMethodStart]
										ExtensionServernameStart := CompressionMethodStart + 1 + uint16(CompressionMethodLength) + 2 //2是扩展长度
										ExtensionServernameLength := binary.BigEndian.Uint16(payload[ExtensionServernameStart+2 : ExtensionServernameStart+4])
										if ExtensionServernameLength != 0 {
											SNIServernameLength := binary.BigEndian.Uint16(payload[ExtensionServernameStart+7 : ExtensionServernameStart+9])
											ServerName := string(payload[ExtensionServernameStart+9 : ExtensionServernameStart+9+SNIServernameLength])
											fmt.Println("ServerName: ", ServerName)
											tlsServerNames[ServerName]++
										}
									}

									/*
									* If TLS Handshake HELLO is SERVER_HELLO
									 */
									if TLSRecordHandshakeMessageType == tlsRecordHandshakeServerHello {
										// TLS in Handshake layer
										TLSHandshakeLayerVersion := binary.BigEndian.Uint16(payload[9:11])

										fmt.Println("TLS Version", translateTLSVersions(TLSHandshakeLayerVersion))

										// Detect cipher block start byte
										sessionIDLength := payload[43]
										cipherSuitesStart := 43 + 1 + sessionIDLength // session length offset (43B) + length byte (1B) + sessionIDLength

										// Detect length of cipher part
										// (Not needed for server part, because only one cipher is suggested by server)
										ciphersServersList := list.New()
										// Walk through all ciphers and count occurances
										// (no walking needed, because there is only one cipher suggested)
										cipherpos := cipherSuitesStart
										cipher := binary.BigEndian.Uint16(payload[cipherpos : cipherpos+2])
										ciphersServersList.PushBack(translateCipher(cipher)) // Increment counter for this cipher
										fmt.Println("Server Ciphers-Suites:")
										for i := ciphersServersList.Front(); i != nil; i = i.Next() {
											fmt.Println(i.Value)
										}
									}
									if payload[0] == tlsRecordAlert {
										/*
										* If there is an alert message
										* Search for any Handshake failures
										 */
										tlsAlertLength := binary.BigEndian.Uint16(payload[3:5])
										// Alerts need to have length 2 bytes
										if tlsAlertLength == 2 {
											tlsAlertDescription := payload[6]
											fmt.Println("TLS Alert", translateAlert(uint16(tlsAlertDescription)))
										}
									}

								}
							}
						}
					}
				// 17：udp
				case 17:
					udpLayer := packet.Layer(layers.LayerTypeUDP)
					if udpLayer != nil {
						udp, _ := udpLayer.(*layers.UDP)

						// 只解析53端口的dns
						if udp.SrcPort == 53 || udp.DstPort == 53 {
							dnsLayer := packet.Layer(layers.LayerTypeDNS)
							if dnsLayer != nil {
								dns_num++
								fmt.Println("--------------------------------------------------------------------")
								fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
								fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
								// Ethernet type is typically IPv4 but could be ARP or other
								fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
								fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
								//fmt.Println("Protocol: ", ip.Protocol)
								fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
								fmt.Println("Protocol: DNS")
								dns, _ := dnsLayer.(*layers.DNS)
								//dnsOpCode := int(dns.OpCode)
								dnsResponseCode := int(dns.ResponseCode)
								dnsANCount := int(dns.ANCount)
								if (dnsANCount == 0 && dnsResponseCode > 0) || (dnsANCount > 0) {
									for _, dnsQuestion := range dns.Questions {
										fmt.Println("    DNS OpCode: ", strconv.Itoa(int(dns.OpCode)))
										fmt.Println("    DNS ResponseCode: ", dns.ResponseCode.String())
										fmt.Println("    DNS AnswersCount: ", strconv.Itoa(dnsANCount))
										fmt.Println("    DNS Question: ", string(dnsQuestion.Name))
										dnsQuestionDomains[string(dnsQuestion.Name)]++
										if dnsANCount > 0 {
											for _, dnsAnswer := range dns.Answers {
												if dnsAnswer.IP.String() != "<nil>" {
													fmt.Println("    DNS Answer: ", dnsAnswer.IP.String())
												}
											}

										}
									}
								}
							}
						}
					}
				}
			}
		}

	}
}

func main() {

	httpHosts = make(map[string]int)
	tlsServerNames = make(map[string]int)
	dnsQuestionDomains = make(map[string]int)

	// Get pcap file flag
	var argPcapFile = flag.String("d", "", "Path to .pcap file.")
	flag.Parse()

	// Open file instead of device
	handle, err = pcap.OpenOffline(*argPcapFile)
	if err != nil {
		panic(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "tcp||udp"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		//println(packet)
		printPacketInfo(packet) // Do something with a packet here.
	}

	fmt.Println("--------------------------------------------------------------------")
	fmt.Println("Count")
	fmt.Println("http: ", http_num)
	fmt.Println("tls: ", tls_num)
	fmt.Println("dns: ", dns_num)

	fmt.Println("\nhosts in http:")
	for host := range httpHosts {
		fmt.Print(host)
		fmt.Print("  ")
	}
	fmt.Println("\n\nServerName in tlsClientHello:")
	for servername := range tlsServerNames {
		fmt.Print(servername)
		fmt.Print("  ")
	}
	fmt.Println("\n\nQuestionDomain in DNS:")
	for domain := range dnsQuestionDomains {
		fmt.Print(domain)
		fmt.Print("  ")
	}
}
