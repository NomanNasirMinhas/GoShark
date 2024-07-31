package main

import (
	"context"
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
	"github.com/gorilla/websocket"

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

// Slice to store connected WebSocket clients
var clients []*websocket.Conn
var handles []*pcap.Handle
var capturePackets []gopacket.Packet
var mu sync.Mutex
var protocols_list map[string]map[int]string

// Handler function for WebSocket connection
func wsHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade the HTTP request to a WebSocket connection
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Println("Error upgrading:", err)
		return
	}
	fmt.Println("Client connected -> ", conn.RemoteAddr())
	defer conn.Close()

	mu.Lock()
	clients = append(clients, conn)
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
	for i, c := range clients {
		if c == conn {
			clients = append(clients[:i], clients[i+1:]...)
			break
		}
	}
	mu.Unlock()
}

// Function to broadcast messages to all connected clients
func broadcastMessage(message string) {
	mu.Lock()
	defer mu.Unlock()

	for _, conn := range clients {
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
	http.HandleFunc("/ws", wsHandler)

	// Start the WebSocket server in a new goroutine
	go func() {
		fmt.Println("WebSocket server starting on :4444")
		if err := http.ListenAndServe("0.0.0.0:4444", nil); err != nil {
			fmt.Println("Error starting server:", err)
		} else {
			fmt.Println("Server running on 4444 port")
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

// PacketInfo holds the decoded information from the packet
type PacketInfo struct {
	Timestamp       time.Time        `json:"timestamp,omitempty"`
	CaptureLength   int              `json:"cap_length,omitempty"`
	Length          int              `json:"length,omitempty"`
	Ethernet        *layers.Ethernet `json:"ethernet,omitempty"`
	IP              *layers.IPv4     `json:"ip,omitempty"`
	IPv6            *layers.IPv6     `json:"ipv6,omitempty"`
	ARP             *layers.ARP      `json:"arp,omitempty"`
	TCP             *layers.TCP      `json:"tcp,omitempty"`
	UDP             *layers.UDP      `json:"udp,omitempty"`
	ICMPv4          *layers.ICMPv4   `json:"icmpv4,omitempty"`
	ICMPv6          *layers.ICMPv6   `json:"icmpv6,omitempty"`
	Payload         []byte           `json:"payload,omitempty"`
	DecodeError     error            `json:"decode_error,omitempty"`
	SourceMAC       string           `json:"source_mac,omitempty"`
	DestinationMac  string           `json:"destination_mac,omitempty"`
	SourceIP4       string           `json:"source_ip_4,omitempty"`
	DestinationIP4  string           `json:"destination_ip_4,omitempty"`
	SourceIP6       string           `json:"source_ip_6,omitempty"`
	DestinationIP6  string           `json:"destination_ip_6,omitempty"`
	SrcPort         string           `json:"src_port,omitempty"`
	DstPort         string           `json:"dst_port,omitempty"`
	AppProtocol     string           `json:"protocol,omitempty"`
	L2Protocol      string           `json:"l2_protocol,omitempty"`
	L1Protocol      string           `json:"l1_protocol,omitempty"`
	Details         string           `json:"details,omitempty"`
	Color           string           `json:"color,omitempty"`
	SourceHost      string           `json:"source_host,omitempty"`
	DestinationHost string           `json:"destination_host,omitempty"`
}

// PacketToJSON converts a gopacket.Packet to a JSON string
func PacketToJSON(packet gopacket.Packet) (string, error) {
	var packetInfo PacketInfo

	packetInfo.Timestamp = packet.Metadata().Timestamp
	// Length is the size of the original packet.  Should always be >=
	// CaptureLength.
	packetInfo.Length = packet.Metadata().Length
	packetInfo.CaptureLength = packet.Metadata().CaptureLength

	// Decode layers and check for nil pointers
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if ethernetPacket, ok := ethLayer.(*layers.Ethernet); ok {
			packetInfo.Ethernet = ethernetPacket
			packetInfo.SourceMAC = ethernetPacket.SrcMAC.String()
			packetInfo.DestinationMac = ethernetPacket.DstMAC.String()
		}
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ipPacket, ok := ipLayer.(*layers.IPv4); ok {
			packetInfo.IP = ipPacket
			packetInfo.SourceIP4 = ipPacket.SrcIP.String()
			packetInfo.DestinationIP4 = ipPacket.DstIP.String()
			src_list, err := net.LookupAddr(packetInfo.SourceIP4)
			if err == nil {
				for _, hostname := range src_list {
					packetInfo.SourceHost = hostname
					break
				}
			}
			dst_src, err := net.LookupAddr(packetInfo.DestinationIP4)
			if err == nil {
				for _, hostname := range dst_src {
					packetInfo.DestinationHost = hostname
					break
				}
			}
			packetInfo.L2Protocol = l2Protocols[uint8(ipPacket.Protocol)]
		}
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		if ipv6Packet, ok := ipv6Layer.(*layers.IPv6); ok {
			packetInfo.IPv6 = ipv6Packet
			packetInfo.SourceIP6 = ipv6Packet.SrcIP.String()
			packetInfo.DestinationIP6 = ipv6Packet.DstIP.String()
		}
	}
	if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
		if arpPacket, ok := arpLayer.(*layers.ARP); ok {
			packetInfo.ARP = arpPacket
		}
	}
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		if tcpPacket, ok := tcpLayer.(*layers.TCP); ok {
			packetInfo.TCP = tcpPacket
			packetInfo.SrcPort = tcpPacket.SrcPort.String()
			packetInfo.DstPort = tcpPacket.DstPort.String()
			// packetInfo.AppProtocol, packetInfo.Color = GetAppProtocol(uint8(packetInfo.IP.Protocol), uint16(tcpPacket.DstPort))
			// println("Destination Port", int(packetInfo.IP.Protocol), int(tcpPacket.DstPort))
			packetInfo.AppProtocol, packetInfo.Color = GetProtocolDescription(protocols_list, int(packetInfo.IP.Protocol), int(tcpPacket.DstPort))
		}
	}
	if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		if udpPacket, ok := udpLayer.(*layers.UDP); ok {
			packetInfo.UDP = udpPacket
		}
	}
	if icmpv4Layer := packet.Layer(layers.LayerTypeICMPv4); icmpv4Layer != nil {
		if icmpv4Packet, ok := icmpv4Layer.(*layers.ICMPv4); ok {
			packetInfo.ICMPv4 = icmpv4Packet
		}
	}
	if icmpv6Layer := packet.Layer(layers.LayerTypeICMPv6); icmpv6Layer != nil {
		if icmpv6Packet, ok := icmpv6Layer.(*layers.ICMPv6); ok {
			packetInfo.ICMPv6 = icmpv6Packet
		}
	}

	if packet.ApplicationLayer() != nil {
		packetInfo.Details = string(packet.ApplicationLayer().Payload())
	} else if packet.TransportLayer() != nil {
		packetInfo.Details = string(packet.TransportLayer().LayerPayload())
	} else if packet.NetworkLayer() != nil {
		packetInfo.Details = string(packet.NetworkLayer().LayerPayload())
	} else {
		packetInfo.Details = string(packet.LinkLayer().LayerPayload())
	}

	// Get payload and check for nil
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		packetInfo.Payload = appLayer.Payload()
	}

	// Include any error occurred during decoding
	if err_layer := packet.ErrorLayer(); err_layer != nil {
		packetInfo.DecodeError = err_layer.Error()
	}

	// Convert to JSON
	jsonData, err := json.Marshal(packetInfo)
	if err != nil {
		return "", err
	}

	return string(jsonData), nil
}

func (a *App) IsRoot() bool {
	currentUser, err := user.Current()
	if err != nil {
		log.Fatalf("[isRoot] Unable to get current user: %s", err)
	}
	return currentUser.Username == "root"
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

		packetStr, err := PacketToJSON(packet)
		if err == nil {
			broadcastMessage(packetStr)
		} else {
			println("Error Parsing Packet", err)
		}
	}
}

func (a *App) StopCapture() {
	mu.Lock()
	defer mu.Unlock()

	for _, handle := range handles {
		handle.Close()
	}
	handles = handles[:0]
	capturePackets = capturePackets[:0]
	println("Packet Capture Stopped")
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
