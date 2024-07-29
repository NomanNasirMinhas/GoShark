package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/user"
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
var mu sync.Mutex
var handles []*pcap.Handle

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

	a.ctx = ctx

}

// PacketInfo holds the decoded information from the packet
type PacketInfo struct {
	Timestamp   time.Time        `json:"timestamp,omitempty"`
	Length      int              `json:"length,omitempty"`
	Ethernet    *layers.Ethernet `json:"ethernet,omitempty"`
	IP          *layers.IPv4     `json:"ip,omitempty"`
	IPv6        *layers.IPv6     `json:"ipv6,omitempty"`
	ARP         *layers.ARP      `json:"arp,omitempty"`
	TCP         *layers.TCP      `json:"tcp,omitempty"`
	UDP         *layers.UDP      `json:"udp,omitempty"`
	ICMPv4      *layers.ICMPv4   `json:"icmpv4,omitempty"`
	ICMPv6      *layers.ICMPv6   `json:"icmpv6,omitempty"`
	Payload     []byte           `json:"payload,omitempty"`
	DecodeError error            `json:"decode_error,omitempty"`
}

// PacketToJSON converts a gopacket.Packet to a JSON string
func PacketToJSON(packet gopacket.Packet) (string, error) {
	var packetInfo PacketInfo

	packetInfo.Timestamp = packet.Metadata().Timestamp
	packetInfo.Length = len(packet.Data())

	// Decode layers and check for nil pointers
	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		if ethernetPacket, ok := ethLayer.(*layers.Ethernet); ok {
			packetInfo.Ethernet = ethernetPacket
		}
	}
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		if ipPacket, ok := ipLayer.(*layers.IPv4); ok {
			packetInfo.IP = ipPacket
		}
	}
	if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		if ipv6Packet, ok := ipv6Layer.(*layers.IPv6); ok {
			packetInfo.IPv6 = ipv6Packet
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

func (a *App) StartCapture(iface string, promisc bool, filter string, export bool) {
	snaplen := int32(1600 * 2)

	pcap_handle, err := pcap.OpenLive(iface, snaplen, promisc, pcap.BlockForever)
	if err != nil {
		log.Panicln(err)
	}
	defer pcap_handle.Close()
	var w *pcapgo.Writer
	if export {
		current_time := time.Now().String()
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

	mu.Lock()
	handles = append(handles, pcap_handle)
	mu.Unlock()

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
	println("Packet Capture Stopped")
}

func (a *App) Greet(name string) string {
	return fmt.Sprintf("Hello %s, It's show time!", name)
}
