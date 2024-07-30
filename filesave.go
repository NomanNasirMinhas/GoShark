package main

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/valyala/fasthttp"
)

func saveFileFromPacket(packet gopacket.Packet) {
	// Extract application layer
	appLayer := packet.ApplicationLayer()
	if appLayer != nil {
		payload := appLayer.Payload()
		// Detect HTTP traffic
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcp, _ := packet.TransportLayer().(*layers.TCP)
			if tcp.DstPort == 80 || tcp.DstPort == 443 {
				saveHTTPFile(payload)
			}
		}
		// Detect FTP traffic
		if packet.TransportLayer().LayerType() == layers.LayerTypeTCP {
			tcp, _ := packet.TransportLayer().(*layers.TCP)
			if tcp.DstPort == 21 {
				saveFTPFile(payload)
			}
		}
	}
}

func saveHTTPFile(payload []byte) {
	req := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(req)

	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseResponse(resp)

	// Create a bufio.Reader from the payload
	reader := bufio.NewReader(bytes.NewReader(payload))

	// Parse the HTTP request or response
	if err := req.Read(reader); err == nil {
		// Handle HTTP request here (e.g., GET, POST)
		body := req.Body()
		if len(body) > 0 {
			saveToFile("http_request", body)
		}
	} else if err := resp.Read(reader); err == nil {
		// Handle HTTP response here (e.g., 200 OK)
		body := resp.Body()
		if len(body) > 0 {
			saveToFile("http_response", body)
		}
	}
}

func saveFTPFile(payload []byte) {
	// Extract FTP commands and data
	data := string(payload)
	if strings.HasPrefix(data, "STOR") || strings.HasPrefix(data, "RETR") {
		// Assume the payload contains the file data after an FTP STOR or RETR command
		saveToFile("ftp_file", payload)
	}
}

func saveToFile(prefix string, data []byte) {
	fileName := fmt.Sprintf("%s_%d.bin", prefix, time.Now().UnixNano())
	err := os.WriteFile(fileName, data, 0644)
	if err != nil {
		log.Printf("Failed to save file: %v", err)
	} else {
		fmt.Printf("Saved file: %s\n", fileName)
	}
}
