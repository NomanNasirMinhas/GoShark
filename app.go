package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"
	"github.com/miekg/dns"

	"github.com/VirusTotal/gyp/ast"
	"github.com/m-chrome/go-suricataparser"

	"encoding/json"
)

// App struct
type App struct {
	ctx context.Context
}

// Define the upgrader which will upgrade the HTTP connection to a WebSocket connection
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// Allow all origins (in production, it's better to set this explicitly)
	CheckOrigin: func(r *http.Request) bool { return true },
}

var suricataRules []*suricataparser.Rule

const suricataRulesDir = "suricataRules"
const yaraRulesDir = "yaraRules"

// Slice to store connected WebSocket clients
var clients1 []*websocket.Conn
var clients2 []*websocket.Conn
var clients3 []*websocket.Conn
var handles []*pcap.Handle
var capturePackets []gopacket.Packet
var mu sync.Mutex
var protocols_list map[string]map[int]string
var yaraRules []*ast.Rule
var pack_info []PacketLayers

type WsMessage struct {
	Type string
	Msg  string
}

// Handler function for WebSocket connection
func ws1Handler(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP request to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading:", err)
		return
	}
	fmt.Println("Client connected -> ", conn.RemoteAddr())
	defer conn.Close()

	mu.Lock()
	clients1 = append(clients1, conn)
	mu.Unlock()

	// Listen for messages from the client
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("Client disconnected:", err)
			break
		}
	}

	mu.Lock()
	// Remove the client from the list
	for i, c := range clients1 {
		if c == conn {
			clients1 = append(clients1[:i], clients1[i+1:]...)
			break
		}
	}
	mu.Unlock()
}

// Handler function for WebSocket connection
func ws2Handler(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP request to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading:", err)
		return
	}
	fmt.Println("Client connected -> ", conn.RemoteAddr())
	defer conn.Close()

	mu.Lock()
	clients2 = append(clients2, conn)
	mu.Unlock()

	// Listen for messages from the client
	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("Client disconnected:", err)
			break
		}

		// go func() {
		msg_token := strings.Split(string(msg), "_")
		fmt.Printf("%s\n", msg_token)
		if msg_token[0] == "pack-info" {
			id, err := strconv.ParseInt(msg_token[1], 10, 64)
			if err == nil {
				fmt.Printf("Getting packet details of %d\n", id)
				for _, p := range pack_info {
					if p.PacketID == id {
						jsonData, err := json.Marshal(p)
						if err == nil {
							packetStr := string(jsonData)
							// println(packetStr)
							broadcastMessage2(packetStr)
						}
					}
				}
				// Convert to JSON

			}
		}
		// }()

	}

	mu.Lock()
	// Remove the client from the list
	for i, c := range clients2 {
		if c == conn {
			clients2 = append(clients2[:i], clients2[i+1:]...)
			break
		}
	}
	mu.Unlock()
}

// Handler function for WebSocket connection
func ws3Handler(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP request to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading:", err)
		return
	}
	fmt.Println("Client connected -> ", conn.RemoteAddr())
	defer conn.Close()

	mu.Lock()
	clients3 = append(clients3, conn)
	mu.Unlock()

	// Listen for messages from the client
	for {
		_, _, err := conn.ReadMessage()
		if err != nil {
			fmt.Println("Client disconnected:", err)
			break
		}

	}

	mu.Lock()
	// Remove the client from the list
	for i, c := range clients3 {
		if c == conn {
			clients3 = append(clients3[:i], clients3[i+1:]...)
			break
		}
	}
	mu.Unlock()
}

// Function to broadcast messages to all connected clients
func broadcastMessage1(message string) {
	// print(".")
	mu.Lock()
	defer mu.Unlock()

	for _, conn := range clients1 {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			fmt.Println("Error sending message:", err)
		}
	}
}

// Function to broadcast messages to all connected clients
func broadcastMessage2(message string) {
	print("sending packet details message\n")
	mu.Lock()
	defer mu.Unlock()

	for _, conn := range clients2 {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			fmt.Println("Error sending message:", err)
		}
	}
}

func broadcastMessage3(message string) {
	// print(message + "\n")
	mu.Lock()
	defer mu.Unlock()

	for _, conn := range clients3 {
		if err := conn.WriteMessage(websocket.TextMessage, []byte(message)); err != nil {
			fmt.Println("Error sending message:", err)
		}
	}
}

// NewApp creates a new App application struct
func NewApp() *App {
	return &App{}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	http.HandleFunc("/ws1", ws1Handler)

	// Start the WebSocket server in a new goroutine
	go func() {
		fmt.Println("WebSocket server starting on :4444")
		if err := http.ListenAndServe("0.0.0.0:4444", nil); err != nil {
			fmt.Println("Error starting server:", err)
		} else {
			fmt.Println("Server running on 4444 port")
		}
	}()

	http.HandleFunc("/ws2", ws2Handler)
	go func() {
		fmt.Println("WebSocket server starting on :4445")
		if err := http.ListenAndServe("0.0.0.0:4445", nil); err != nil {
			fmt.Println("Error starting server:", err)
		} else {
			fmt.Println("Server running on 4445 port")
		}
	}()

	http.HandleFunc("/ws3", ws3Handler)
	go func() {
		fmt.Println("WebSocket server starting on :4446")
		if err := http.ListenAndServe("0.0.0.0:4446", nil); err != nil {
			fmt.Println("Error starting server:", err)
		} else {
			fmt.Println("Server running on 4445 port")
		}
	}()

	// Load protocols from CSV
	var err error
	protocols_list, err = LoadProtocols("ports.csv")
	if err != nil {
		fmt.Printf("Error loading protocols: %v\n", err)
	}

	a.ctx = ctx

}

type PacketInfoArr struct {
	Packets []PacketInfo `json:"packets,omitempty"`
}

type AlertMessage struct {
	Timestamp    int64  `json:"timestamp,omitempty"`
	AlertType    int    `json:"alert_type,omitempty"`
	AlertMessage string `json:"alert_msg,omitempty"`
}

// PacketInfo holds the decoded information from the packet

type PacketLayers struct {
	PacketID      int64          `json:"packet_id,omitempty"`
	Timestamp     int64          `json:"timestamp,omitempty"`
	SuricataAlert []AlertMessage `json:"suricata_alert,omitempty"`
	YaraAlert     []AlertMessage `json:"yara_alert,omitempty"`
	HasAlert      bool           `json:"has_alert,omitempty"`
	Layers        []LayerData    `json:"layers,omitempty"`
	PacketString  string         `json:"packet_string,omitempty"`
	PacketHex     []byte         `json:"packet_hex,omitempty"`
}

type PacketInfo struct {
	PacketID      int64  `json:"packet_id,omitempty"`
	Timestamp     int64  `json:"timestamp,omitempty"`
	CaptureLength int    `json:"cap_length,omitempty"`
	Length        int    `json:"length,omitempty"`
	Source        string `json:"source,omitempty"`
	Destination   string `json:"destination,omitempty"`
	SrcPort       string `json:"src_port,omitempty"`
	DstPort       string `json:"dst_port,omitempty"`
	AppProtocol   string `json:"app_protocol,omitempty"`
	Color         string `json:"color,omitempty"`
	HasAlert      bool   `json:"has_alert,omitempty"`
	Protocol      string `json:"protocol,omitempty"`
	PacketString  string `json:"packet_string,omitempty"`
}

var Max_Pack_ID = 0

// PacketToJSON conver1ts a gopacket.Packet to a JSON string
func PacketToJSON(packet gopacket.Packet) (PacketLayers, error) {
	var packetInfo PacketInfo
	var packetDetails PacketLayers

	Max_Pack_ID = Max_Pack_ID + 1
	packetInfo.PacketID = int64(Max_Pack_ID)
	packetDetails.PacketID = int64(Max_Pack_ID)
	packetDetails.Layers, packetInfo.Protocol = GetLayers(packet)
	packetInfo.Timestamp = packet.Metadata().Timestamp.Unix()
	// packetInfo.DataDump = packet.Dump()
	packetDetails.PacketString = packet.String()
	packetInfo.PacketString = packet.String()
	packetDetails.PacketHex = packet.Data()
	// Length is the size of the original packet.  Should always be >=
	// CaptureLength.
	packetInfo.Length = packet.Metadata().Length
	packetInfo.CaptureLength = packet.Metadata().CaptureLength

	// Decode layers and check for nil pointers
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if ethernetPacket, ok := ethLayer.(*layers.Ethernet); ok {
			packetInfo.Source = strings.ToUpper(ethernetPacket.SrcMAC.String())
			packetInfo.Destination = strings.ToUpper(ethernetPacket.DstMAC.String())
		}
	}
	var ipProtocol layers.IPProtocol
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ipPacket, ok := ipLayer.(*layers.IPv4); ok {
			packetInfo.Source = ipPacket.SrcIP.String()
			packetInfo.Destination = ipPacket.DstIP.String()
			ipProtocol = ipPacket.Protocol
			// src_list, err := net.LookupAddr(packetInfo.SourceIP4)
			// if err == nil {
			// 	packetInfo.SourceHost = strings.Join(src_list, ", ")
			// }
			// dst_src, err := net.LookupAddr(packetInfo.DestinationIP4)
			// if err == nil {
			// 	packetInfo.DestinationHost = strings.Join(dst_src, ", ")
			// }
			// packetInfo.L2Protocol = l2Protocols[uint8(ipPacket.Protocol)]
		}
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		if ipv6Packet, ok := ipv6Layer.(*layers.IPv6); ok {
			packetInfo.Source = ipv6Packet.SrcIP.String()
			packetInfo.Destination = ipv6Packet.DstIP.String()
		}
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcpPacket, ok := tcpLayer.(*layers.TCP); ok {
			src_port_tokens := strings.Split(tcpPacket.SrcPort.String(), "(")
			dst_port_tokens := strings.Split(tcpPacket.DstPort.String(), "(")

			packetInfo.SrcPort = src_port_tokens[0]
			packetInfo.DstPort = dst_port_tokens[0]

			if len(src_port_tokens) > 1 {
				packetInfo.AppProtocol = strings.ToUpper(strings.Trim(src_port_tokens[1], ")"))
			}

			if len(dst_port_tokens) > 1 {
				packetInfo.AppProtocol = strings.ToUpper(strings.Trim(dst_port_tokens[1], ")"))
			}

			// packetInfo.AppProtocol, packetInfo.Color = GetAppProtocol(uint8(packetInfo.IP.Protocol), uint16(tcpPacket.DstPort))
			// println("Destination Port", int(packetInfo.IP.Protocol), int(tcpPacket.DstPort))
			_, packetInfo.Color = GetProtocolDescription(protocols_list, int(ipProtocol), int(tcpPacket.DstPort), int(tcpPacket.SrcPort))
		}
	}

	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udpPacket, ok := udpLayer.(*layers.UDP); ok {
			src_port_tokens := strings.Split(udpPacket.SrcPort.String(), "(")
			dst_port_tokens := strings.Split(udpPacket.DstPort.String(), "(")

			packetInfo.SrcPort = src_port_tokens[0]
			packetInfo.DstPort = dst_port_tokens[0]

			if len(src_port_tokens) > 1 {
				packetInfo.AppProtocol = strings.ToUpper(strings.Trim(src_port_tokens[1], ")"))
			}

			if len(dst_port_tokens) > 1 {
				packetInfo.AppProtocol = strings.ToUpper(strings.Trim(dst_port_tokens[1], ")"))
			}
			// packetInfo.AppProtocol, packetInfo.Color = GetAppProtocol(uint8(packetInfo.IP.Protocol), uint16(tcpPacket.DstPort))
			// println("Destination Port", int(packetInfo.IP.Protocol), int(tcpPacket.DstPort))
			_, packetInfo.Color = GetProtocolDescription(protocols_list, int(ipProtocol), int(udpPacket.DstPort), int(udpPacket.SrcPort))
		}
	}

	if arpLayer := packet.Layer(layers.LayerTypeDNS); arpLayer != nil {
		if arpPacket, ok := arpLayer.(*layers.ARP); ok {
			packetInfo.SrcPort = string(arpPacket.DstHwAddress)
			packetInfo.DstPort = string(arpPacket.DstHwAddress)

			fmt.Printf("ARP %s and %s\n", packetInfo.SrcPort, packetInfo.DstPort)
		}
	}

	if ICMPv6NeighborSolicitationLayer := packet.Layer(layers.LayerTypeICMPv6NeighborSolicitation); ICMPv6NeighborSolicitationLayer != nil {
		if ICMPv6NeighborSolicitationPacket, ok := ICMPv6NeighborSolicitationLayer.(*layers.ARP); ok {
			packetInfo.SrcPort = string(ICMPv6NeighborSolicitationPacket.SourceHwAddress)
			packetInfo.DstPort = string(ICMPv6NeighborSolicitationPacket.DstHwAddress)
			fmt.Printf("ICMPv6NeighborSolicitationLayer %s and %s\n", packetInfo.SrcPort, packetInfo.DstPort)
		}
	}

	if len(packetInfo.AppProtocol) == 0 {
		packetInfo.AppProtocol = packetInfo.Protocol
	}

	// Convert to JSON
	jsonData, err := json.Marshal(packetInfo)
	if err != nil {
		return packetDetails, err
	}
	broadcastMessage1(string(jsonData))
	return packetDetails, nil
}

func (a *App) IsRoot() bool {
	switch runtime.GOOS {
	case "windows":
		return true
	case "linux", "darwin":
		currentUser, err := user.Current()
		if err != nil {
			log.Fatalf("[isRoot] Unable to get current user: %s", err)
		}
		return currentUser.Username == "root"
	default:
		log.Printf("Unsupported platform: %s\n", runtime.GOOS)
		return false
	}
}

// IsRunningAsAdmin checks if the program is running with administrative (Windows) or root (Linux/macOS) privileges.
func IsRunningAsAdmin() bool {
	switch runtime.GOOS {
	case "windows":
		return isWindowsAdmin()
	case "linux", "darwin":
		return isRoot()
	default:
		log.Printf("Unsupported platform: %s\n", runtime.GOOS)
		return false
	}
}

// isWindowsAdmin checks if the program is running with administrative privileges on Windows.
func isWindowsAdmin() bool {
	// The windows package is not part of the standard library, so import it only if running on Windows.
	// Import the package with: "golang.org/x/sys/windows"
	// The implementation checks if the process token has elevated privileges.
	// import (
	// 	"golang.org/x/sys/windows"
	// )

	// var sid *windows.SID
	// // Create a SID for the BUILTIN\Administrators group.
	// if err := windows.AllocateAndInitializeSid(&windows.SECURITY_NT_AUTHORITY, 2,
	// 	windows.SECURITY_BUILTIN_DOMAIN_RID, windows.DOMAIN_ALIAS_RID_ADMINS,
	// 	0, 0, 0, 0, 0, 0, &sid); err != nil {
	// 	log.Fatalf("AllocateAndInitializeSid: %v", err)
	// 	return false
	// }
	// defer windows.FreeSid(sid)

	// token := windows.Token(0)
	// isMember, err := token.IsMember(sid)
	// if err != nil {
	// 	log.Fatalf("Token.IsMember: %v", err)
	// 	return false
	// }
	return true
}

// isRoot checks if the program is running with root privileges on Linux/macOS.
func isRoot() bool {
	return os.Geteuid() == 0
}

func (a *App) GetAllDevices() string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Panicln(err)
	}

	var devicesStr string
	for _, device := range devices {
		interface_ip_if_exists := "0"
		if len(device.Addresses) > 0 {
			interface_ip_if_exists = device.Addresses[0].IP.String()
		}
		devicesStr += fmt.Sprintf("%s:%s,", device.Name, interface_ip_if_exists)
	}

	return devicesStr
}

func (a *App) StartCapture(iface string, promisc bool, filter string, export bool, saveFiles bool) {
	Max_Pack_ID = 0
	capturePackets = capturePackets[:0]
	pack_info = pack_info[:0]
	snaplen := int32(1600 * 2)

	pcap_handle, err := pcap.OpenLive(iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		log.Panicln(err)
	}
	defer pcap_handle.Close()

	var w *pcapgo.Writer
	if export {
		current_time := time.Now().Format("20060102-150405")
		file_name := fmt.Sprintf("output_%s.pcap", current_time)
		println("Writing to file: ", file_name)
		// Create pcap file and writer
		f, err := os.Create(file_name)
		if err != nil {
			log.Fatal(err)
		}
		defer f.Close()
		w = pcapgo.NewWriter(f)
		w.WriteFileHeader(uint32(snaplen), pcap_handle.LinkType())
	}

	if filter != "" {
		if err := pcap_handle.SetBPFFilter(filter); err != nil {
			log.Panicln(err)
		}
	}

	source := gopacket.NewPacketSource(pcap_handle, pcap_handle.LinkType())
	println("Packet Capture Started")
	for packet := range source.Packets() {
		if export {
			err := w.WritePacket(packet.Metadata().CaptureInfo, packet.Data())
			if err != nil {
				log.Fatal(err)
			}
		}

		if saveFiles {
			handlePacketForSaving(packet)
		}

		packLayers, _ := PacketToJSON(packet)

		// go func() {

		pack_info = append(pack_info, packLayers)
		if len(suricataRules) > 0 {
			// println("Checking for Suricata")
			packLayers = checkforSuricataAlert(packLayers)
		}

		if len(yaraRules) > 0 {
			packLayers = checkForYaraMatch(packet, packLayers)
		}

		if packLayers.HasAlert {
			jsonData, err := json.Marshal(packLayers)
			if err == nil {
				alert_msg := string(jsonData)
				broadcastMessage3(alert_msg)
			}
		}
		// }()
	}
}

func (a *App) StopCapture() bool {
	mu.Lock()
	defer mu.Unlock()

	for _, handle := range handles {
		handle.Close()
	}
	handles = handles[:0]
	capturePackets = capturePackets[:0]
	println("Packet Capture Stopped")
	return true
}

// Create the suricataRules folder if it does not exist
func createSuricataRulesDir() {
	if _, err := os.Stat(suricataRulesDir); os.IsNotExist(err) {
		err := os.Mkdir(suricataRulesDir, os.ModePerm)
		if err != nil {
			fmt.Printf("Error creating directory: %s\n", err)
			os.Exit(1)
		}
	}
}

func (a *App) ParseSuricataRules(filename string, data []byte) bool {
	println("File Name", filename)
	println("File Data", data)
	// Create or ensure suricataRules directory
	createSuricataRulesDir()

	println("Dir created.")
	// Save the file
	if _, err := os.Stat(suricataRulesDir); os.IsNotExist(err) {
		err := os.Mkdir(suricataRulesDir, os.ModePerm)
		if err != nil {
			fmt.Errorf("error creating directory: %s", err)
			return false
		}
	}
	println("File Saved.")

	// Save the file
	filePath := filepath.Join(suricataRulesDir, filename)
	err := os.WriteFile(filePath, data, 0644)
	if err != nil {
		fmt.Errorf("error saving file: %s", err)
		return false
	}
	println("Data Copied: ", filePath)
	// w.Write([]byte("File uploaded successfully"))

	rules, err := suricataparser.ParseFile(filePath)
	if err != nil {
		fmt.Println("Error parsing rules file:", err)
		return false
	} else {
		println("Rules Len: ", len(rules))
		if len(rules) == 0 {
			fmt.Println("Error parsing rules file:", err)
			return false
		}
		suricataRules = rules
		fmt.Printf("Rule 0: %s", rules[0])
		return true
	}
}

func checkforSuricataAlert(packInfo PacketLayers) PacketLayers {
	for _, rule := range suricataRules {
		if (rule.Action() == "alert" || rule.Action() == "drop") && rule.Enabled {
			// fmt.Printf("Rule -> %s, %s, %s\n\n", rule.Action(), rule.Header(), rule.Enabled)
			header := rule.Header()
			header_split := strings.Split(header, "->")
			header_src := header_split[0]
			header_dst := header_split[1]

			// Extract the protocol, source IP, source port, destination IP, and destination port
			protocol, srcIP, srcPort, dstIP, dstPort := parseHeader(header_src, header_dst)
			// fmt.Printf("Rules -> %s, %s, %s, %s, %s\n\n", protocol, srcIP, srcPort, dstIP, dstPort)
			// Check the protocol
			if checkProtocol(packInfo, protocol) {
				// println("Protocols matched")
				// Check source and destination IP and ports
				if checkIPandPort(packInfo, srcIP, srcPort, dstIP, dstPort) {
					fmt.Printf("Packet matches rule: %s\n", rule.Msg())
					var alert AlertMessage
					alert.AlertMessage = rule.Msg()
					alert.Timestamp = packInfo.Timestamp
					alert.AlertType = 1
					packInfo.SuricataAlert = append(packInfo.SuricataAlert, alert)
					if !packInfo.HasAlert {
						packInfo.HasAlert = true
					}
					return packInfo
				}
			}
		}
	}
	return packInfo
}

// Helper function to parse the header fields
func parseHeader(header_src, header_dst string) (string, string, string, string, string) {
	// Assuming header_src and header_dst are in the format: protocol srcIP srcPort dstIP dstPort
	header_src_parts := strings.Fields(header_src)
	header_dst_parts := strings.Fields(header_dst)

	protocol := header_src_parts[0]
	srcIP := header_src_parts[1]
	srcPort := header_src_parts[2]
	dstIP := header_dst_parts[0]
	dstPort := header_dst_parts[1]

	return protocol, srcIP, srcPort, dstIP, dstPort
}

func str_slice_contains(slice []string, element string) bool {
	for _, v := range slice {
		if strings.ToLower(v) == strings.ToLower(element) {
			return true
		}
	}
	return false
}

// Helper function to check the protocol
func checkProtocol(packet PacketLayers, protocol string) bool {

	for _, layer := range packet.Layers {
		// fmt.Println(strings.ToLower(layer.Protocol), strings.ToLower(protocol))
		if str_slice_contains(layer.Protocol, protocol) {
			return true
		}
	}
	// println("Packet Protocol", p)
	return false
}

// Helper function to check source and destination IP and ports
func checkIPandPort(packet PacketLayers, srcIP, srcPort, dstIP, dstPort string) bool {
	println(srcIP, srcPort, dstIP, dstPort)
	for _, v := range packet.Layers {
		// Check IP addresses
		if srcIP != "any" && v.Src != srcIP {
			return false
		}
		if dstIP != "any" && v.Dst != dstIP {
			return false
		}

		// Check ports
		if srcPort != "any" && v.Src != srcPort {
			return false
		}
		if dstPort != "any" && v.Dst != dstPort {
			return false
		}
		return true
	}
	return false
}

func (a *App) GetPacketStream() []gopacket.Packet {
	return capturePackets
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}

// LoadProtocols loads the protocols from a CSV file into a map.
func LoadProtocols(filePath string) (map[string]map[int]string, error) {
	protocols := make(map[string]map[int]string)

	// Open the CSV file
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	// Create a new CSV reader
	reader := csv.NewReader(file)

	// Read all records from the CSV
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	// Skip the header
	for _, record := range records[1:] {
		protocolType := record[0]
		port, err := strconv.Atoi(record[1])
		if err != nil {
			continue
		}
		description := record[2]

		// Initialize the map for the protocol type if not already done
		if _, ok := protocols[protocolType]; !ok {
			protocols[protocolType] = make(map[int]string)
		}
		protocols[protocolType][port] = description
	}

	return protocols, nil
}

// CheckLibcapAndInstall checks if libpcap is installed and installs it if not.
func (a *App) CheckLibcapAndInstall() int {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		fmt.Printf("Unsupported platform: %s\n", runtime.GOOS)
		return -1
	}

	// Check if libpcap is installed
	if !isLibcapInstalled() {
		fmt.Println("libpcap not found. Installing libpcap-dev...")
		if err := installLibcapDev(); err != nil {
			// return fmt.Errorf("failed to install libpcap-dev: %w", err)
			fmt.Println("Failed to install libpcap-dev.")
			return 0
		}
		fmt.Println("libpcap-dev installed successfully.")
	} else {
		fmt.Println("libpcap is already installed.")
	}
	return 1
}

// isLibcapInstalled checks if libpcap is installed.
func isLibcapInstalled() bool {
	// Try to find the libpcap library
	cmd := exec.Command("ldconfig", "-p")
	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error checking libpcap: %v\n", err)
		return false
	}
	return contains(output, "libpcap")
}

// installLibcapDev installs libpcap-dev using the appropriate package manager.
func installLibcapDev() error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "linux":
		// Detect the package manager and construct the installation command
		if isCommandAvailable("apt-get") {
			cmd = exec.Command("sudo", "apt-get", "install", "-y", "libpcap-dev")
		} else if isCommandAvailable("yum") {
			cmd = exec.Command("sudo", "yum", "install", "-y", "libpcap-devel")
		} else {
			return fmt.Errorf("unsupported package manager on Linux")
		}
	case "darwin":
		cmd = exec.Command("brew", "install", "libpcap")
	default:
		return fmt.Errorf("unsupported platform")
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		fmt.Printf("Error installing libpcap-dev: %v\nOutput: %s\n", err, output)
		return err
	}
	return nil
}

// isCommandAvailable checks if a command is available in the PATH.
func isCommandAvailable(command string) bool {
	_, err := exec.LookPath(command)
	return err == nil
}

// contains checks if a string is present in the byte slice.
func contains(output []byte, substr string) bool {
	return string(output) == substr
}

// QueryDNS queries the specified DNS server for the PTR record of the given IP address and returns the URL.
func QueryDNS(dnsServer, ipAddress string) (string, error) {
	// Reverse the IP address for PTR query
	ipParts := strings.Split(ipAddress, ".")
	for i, j := 0, len(ipParts)-1; i < j; i, j = i+1, j-1 {
		ipParts[i], ipParts[j] = ipParts[j], ipParts[i]
	}
	reversedIP := strings.Join(ipParts, ".") + ".in-addr.arpa."

	// Create a DNS message for the PTR query
	msg := new(dns.Msg)
	msg.SetQuestion(reversedIP, dns.TypePTR)
	msg.RecursionDesired = true

	// Set the DNS server and port
	client := new(dns.Client)
	server := dnsServer + ":53"

	// Send the DNS query
	resp, _, err := client.Exchange(msg, server)
	if err != nil {
		return "", fmt.Errorf("failed to query DNS server: %v", err)
	}

	// Check the response for PTR records
	for _, answer := range resp.Answer {
		if ptr, ok := answer.(*dns.PTR); ok {
			return ptr.Ptr, nil
		}
	}

	return "", fmt.Errorf("no PTR record found for IP address: %s", ipAddress)
}
