package main

// Protocol represents an application layer protocol with a name and color.
type Protocol struct {
	Name  string
	Color string
}

type AppProtocol struct {
	Type        int
	Port        int
	Description string
}

// l2Protocols maps protocol numbers to their corresponding Layer 2 protocol names.
var l2Protocols = map[uint8]string{
	0:   "HOPOPT",
	1:   "ICMP",
	2:   "IGMP",
	3:   "GGP",
	4:   "IPv4",
	5:   "ST",
	6:   "TCP",
	7:   "CBT",
	8:   "EGP",
	9:   "IGP",
	10:  "BBN-RCC-MON",
	11:  "NVP-II",
	12:  "PUP",
	13:  "ARGUS (deprecated)",
	14:  "EMCON",
	15:  "XNET",
	16:  "CHAOS",
	17:  "UDP",
	18:  "MUX",
	19:  "DCN-MEAS",
	20:  "HMP",
	21:  "PRM",
	22:  "XNS-IDP",
	23:  "TRUNK-1",
	24:  "TRUNK-2",
	25:  "LEAF-1",
	26:  "LEAF-2",
	27:  "RDP",
	28:  "IRTP",
	29:  "ISO-TP4",
	30:  "NETBLT",
	31:  "MFE-NSP",
	32:  "MERIT-INP",
	33:  "DCCP",
	34:  "3PC",
	35:  "IDPR",
	36:  "XTP",
	37:  "DDP",
	38:  "IDPR-CMTP",
	39:  "TP++",
	40:  "IL",
	41:  "IPv6",
	42:  "SDRP",
	43:  "IPv6-Route",
	44:  "IPv6-Frag",
	45:  "IDRP",
	46:  "RSVP",
	47:  "GRE",
	48:  "DSR",
	49:  "BNA",
	50:  "ESP",
	51:  "AH",
	52:  "I-NLSP",
	53:  "SWIPE (deprecated)",
	54:  "NARP",
	55:  "Min-IPv4",
	56:  "TLSP",
	57:  "SKIP",
	58:  "IPv6-ICMP",
	59:  "IPv6-NoNxt",
	60:  "IPv6-Opts",
	62:  "CFTP",
	64:  "SAT-EXPAK",
	65:  "KRYPTOLAN",
	66:  "RVD",
	67:  "IPPC",
	69:  "SAT-MON",
	70:  "VISA",
	71:  "IPCV",
	72:  "CPNX",
	73:  "CPHB",
	74:  "WSN",
	75:  "PVP",
	76:  "BR-SAT-MON",
	77:  "SUN-ND",
	78:  "WB-MON",
	79:  "WB-EXPAK",
	80:  "ISO-IP",
	81:  "VMTP",
	82:  "SECURE-VMTP",
	83:  "VINES",
	84:  "IPTM",
	85:  "NSFNET-IGP",
	86:  "DGP",
	87:  "TCF",
	88:  "EIGRP",
	89:  "OSPFIGP",
	90:  "Sprite-RPC",
	91:  "LARP",
	92:  "MTP",
	93:  "AX.25",
	94:  "IPIP",
	95:  "MICP (deprecated)",
	96:  "SCC-SP",
	97:  "ETHERIP",
	98:  "ENCAP",
	100: "GMTP",
	101: "IFMP",
	102: "PNNI",
	103: "PIM",
	104: "ARIS",
	105: "SCPS",
	106: "QNX",
	107: "A/N",
	108: "IPComp",
	109: "SNP",
	110: "Compaq-Peer",
	111: "IPX-in-IP",
	112: "VRRP",
	113: "PGM",
	115: "L2TP",
	116: "DDX",
	117: "IATP",
	118: "STP",
	119: "SRP",
	120: "UTI",
	121: "SMP",
	122: "SM (deprecated)",
	123: "PTP",
	124: "ISIS over IPv4",
	125: "FIRE",
	126: "CRTP",
	127: "CRUDP",
	128: "SSCOPMCE",
	129: "IPLT",
	130: "SPS",
	131: "PIPE",
	132: "SCTP",
	133: "FC",
	134: "RSVP-E2E-IGNORE",
	135: "Mobility Header",
	136: "UDPLite",
	137: "MPLS-in-IP",
	138: "manet",
	139: "HIP",
	140: "Shim6",
	141: "WESP",
	142: "ROHC",
	143: "Ethernet",
	144: "AGGFRAG",
	145: "NSH",
	255: "Reserved",
}

// appProtocols maps protocol numbers and destination ports to their corresponding application layer protocols.
var appProtocols = map[uint8]map[uint16]Protocol{
	6: { // TCP
		20:   {"FTP-DATA", "#FF5733"},
		21:   {"FTP", "#FFBD33"},
		22:   {"SSH", "#75FF33"},
		23:   {"TELNET", "#33FF57"},
		25:   {"SMTP", "#33FFBD"},
		53:   {"DNS", "#3375FF"},
		80:   {"HTTP", "#8D33FF"},
		110:  {"POP3", "#FF33A1"},
		119:  {"NNTP", "#FF3333"},
		143:  {"IMAP", "#33FF57"},
		161:  {"SNMP", "#33FF75"},
		194:  {"IRC", "#33FFC1"},
		443:  {"HTTPS", "#3399FF"},
		445:  {"Microsoft-DS", "#33A1FF"},
		465:  {"SMTPS", "#A133FF"},
		587:  {"SMTP", "#FF33D1"},
		636:  {"LDAPS", "#33FF8D"},
		993:  {"IMAPS", "#FFD133"},
		995:  {"POP3S", "#FF6A33"},
		1080: {"SOCKS", "#FF333F"},
		1433: {"MSSQL", "#A1FF33"},
		1521: {"Oracle", "#FF33FF"},
		2049: {"NFS", "#33FFDF"},
		2083: {"WHMCS", "#FFC133"},
		2087: {"WHM", "#B8FF33"},
		3306: {"MySQL", "#FF3375"},
		3389: {"RDP", "#33FFA1"},
		5432: {"PostgreSQL", "#333FFF"},
		5900: {"VNC", "#338DFF"},
		8080: {"HTTP-Proxy", "#C1FF33"},
		8443: {"HTTPS-Proxy", "#FF3333"},
		// Add more TCP ports as needed
	},
	17: { // UDP
		53:   {"DNS", "#33FF33"},
		67:   {"DHCP", "#33FFF8"},
		68:   {"DHCP", "#3333FF"},
		69:   {"TFTP", "#FF33B5"},
		123:  {"NTP", "#D1FF33"},
		137:  {"NetBIOS-NS", "#FF5733"},
		138:  {"NetBIOS-DGM", "#BD33FF"},
		161:  {"SNMP", "#33C1FF"},
		162:  {"SNMPTRAP", "#FF33A1"},
		445:  {"Microsoft-DS", "#33FF6A"},
		500:  {"ISAKMP", "#33B8FF"},
		514:  {"Syslog", "#FF57FF"},
		520:  {"RIP", "#FFD833"},
		1701: {"L2TP", "#33FF9F"},
		1900: {"SSDP", "#FF6A33"},
		4500: {"IPSec-NAT-T", "#337FFF"},
		5353: {"mDNS", "#FF33E1"},
		1812: {"RADIUS", "#B8FF33"},
		1813: {"RADIUS Accounting", "#FF33C1"},
		// Add more UDP ports as needed
	},
	// Additional transport protocols can be added here
}

// GetL2Protocol returns the Layer 2 protocol name for the given protocol number.
func GetL2Protocol(protocolNumber uint8) string {
	if protocol, found := l2Protocols[protocolNumber]; found {
		return protocol
	}
	return "Unknown"
}

// GetAppProtocol returns the application layer protocol name and color for the given protocol number and port.
func GetAppProtocol(protocolNumber uint8, dst_port uint16, src_port uint16) (string, string) {
	if protocolPorts, found := appProtocols[protocolNumber]; found {
		if protocol, found := protocolPorts[dst_port]; found {
			return protocol.Name, protocol.Color
		} else if protocol, found := protocolPorts[src_port]; found {
			return protocol.Name, protocol.Color
		}
	}
	return "Unknown", ""
}

// GenerateColor generates a unique color hex code for a given index.
func GenerateColor(index int) string {
	colors := []string{
		"#FF5733", "#33FF57", "#3357FF", "#FF33A1", "#33A1FF",
		"#FF33FF", "#33FF8D", "#FFD133", "#FF6A33", "#33C1FF",
		"#B8FF33", "#FF33D1", "#33FFD1", "#FFB833", "#FF33C1",
	}
	return colors[index%len(colors)]
}

// GetProtocolDescription returns the protocol description for a given type and port.
func GetProtocolDescription(protocols map[string]map[int]string, protocolType int, dst_port int, src_port int) (string, string) {
	protocol_type_str := l2Protocols[uint8(protocolType)]
	if protocol, found := protocols[protocol_type_str]; found {
		if description, found := protocol[dst_port]; found {
			color := GenerateColor(dst_port)
			return description, color
		} else if description, found := protocol[src_port]; found {
			color := GenerateColor(src_port)
			return description, color
		}
	}
	return "", ""
}
