package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	netstat "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

func init() {
	logFile, err := os.OpenFile("netmon-server.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatal("Failed to open log file:", err)
	}
	log.SetOutput(logFile)
	log.Println("=== Starting Network Monitor Server ===")
}

type packetDisplay struct {
	Summary     string `json:"summary"`
	Details     string `json:"details"`
	HexDump     string `json:"hex_dump"`
	Application string `json:"application"`
	PID         int32  `json:"pid"`
}

type processInfo struct {
	PID         int32            `json:"PID"`
	Name        string           `json:"Name"`
	Connections []connectionInfo `json:"Connections"`
}

type connectionInfo struct {
	LocalIP    string `json:"LocalIP"`
	LocalPort  uint32 `json:"LocalPort"`
	RemoteIP   string `json:"RemoteIP"`
	RemotePort uint32 `json:"RemotePort"`
}

type clientInfo struct {
	conn      net.Conn
	monitored map[int32]bool
}

var (
	sharedPackets     = make(map[int32][]packetDisplay)
	sharedPacketsMux  sync.Mutex
	sharedProcesses   []processInfo
	sharedProcsMux    sync.Mutex
	activeCaptures    = make(map[int32]chan bool)
	activeCapturesMux sync.Mutex
	clients           = make(map[net.Conn]*clientInfo)
	clientsMux        sync.Mutex
)

func main() {
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "This program must be run as root. Please use sudo.")
		os.Exit(1)
	}

	iface := getDefaultInterface()
	if iface == "" {
		log.Fatal("No network interfaces found")
	}
	log.Printf("Using interface: %s\n", iface)

	listener, err := net.Listen("tcp", ":9090")
	if err != nil {
		log.Fatalf("Failed to start TCP server: %v\n", err)
	}
	defer listener.Close()
	log.Println("TCP server listening on :9090")

	go updateProcessesPeriodically()

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v\n", err)
			continue
		}
		clientsMux.Lock()
		clients[conn] = &clientInfo{
			conn:      conn,
			monitored: make(map[int32]bool),
		}
		clientsMux.Unlock()
		log.Println("New client connected")
		go handleClient(conn)
	}
}

func updateProcessesPeriodically() {
	for {
		procs := getActiveRootProcesses()
		sharedProcsMux.Lock()
		sharedProcesses = procs
		sharedProcsMux.Unlock()
		data, _ := json.Marshal(map[string]interface{}{
			"type": "processes",
			"data": procs,
		})
		log.Printf("Sending process list: %s\n", string(data))
		broadcastToClients(data)
		time.Sleep(2 * time.Second)
	}
}

func handleClient(conn net.Conn) {
	defer func() {
		conn.Close()
		clientsMux.Lock()
		client := clients[conn]
		for pid := range client.monitored {
			stopCapture(pid)
		}
		delete(clients, conn)
		clientsMux.Unlock()
		log.Println("Client disconnected")
	}()

	sharedProcsMux.Lock()
	procData, _ := json.Marshal(map[string]interface{}{
		"type": "processes",
		"data": sharedProcesses,
	})
	sharedProcsMux.Unlock()
	log.Printf("Sending initial process list: %s\n", string(procData))
	fmt.Fprintf(conn, "%s\n", procData)

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		var msg map[string]interface{}
		if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
			log.Printf("Error parsing client message: %v\n", err)
			continue
		}
		if msgType, ok := msg["type"].(string); ok {
			pidFloat, ok := msg["pid"].(float64)
			if !ok {
				log.Println("Invalid PID in control message")
				continue
			}
			pid := int32(pidFloat)
			clientsMux.Lock()
			client := clients[conn]
			clientsMux.Unlock()
			switch msgType {
			case "start_monitor":
				log.Printf("Starting capture for PID %d\n", pid)
				client.monitored[pid] = true
				startCapture(pid)
			case "stop_monitor":
				log.Printf("Stopping capture for PID %d\n", pid)
				delete(client.monitored, pid)
				stopCapture(pid)
			}
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Client connection error: %v\n", err)
	}
}

func broadcastToClients(data []byte) {
	clientsMux.Lock()
	defer clientsMux.Unlock()
	for conn, client := range clients {
		var msg map[string]interface{}
		if err := json.Unmarshal(data, &msg); err != nil {
			log.Printf("Failed to unmarshal broadcast message: %v\n", err)
			continue
		}
		if msg["type"] == "packet" {
			var pktData packetDisplay
			dataBytes, err := json.Marshal(msg["data"])
			if err != nil {
				log.Printf("Failed to marshal packet data: %v\n", err)
				continue
			}
			if err := json.Unmarshal(dataBytes, &pktData); err != nil {
				log.Printf("Failed to unmarshal packet data: %v\n", err)
				continue
			}
			if !client.monitored[pktData.PID] {
				continue
			}
		}
		writer := bufio.NewWriter(conn)
		_, err := writer.Write(data)
		if err != nil {
			log.Printf("Failed to send to client: %v\n", err)
			conn.Close()
			delete(clients, conn)
			continue
		}
		writer.WriteByte('\n')
		if err := writer.Flush(); err != nil {
			log.Printf("Failed to flush to client: %v\n", err)
			conn.Close()
			delete(clients, conn)
		}
	}
}

func getDefaultInterface() string {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("Error finding devices: %v\n", err)
		return ""
	}
	if len(interfaces) == 0 {
		log.Println("No interfaces found")
		return ""
	}
	for _, iface := range interfaces {
		if len(iface.Addresses) > 0 {
			for _, addr := range iface.Addresses {
				if addr.IP.To4() != nil && !addr.IP.IsLoopback() {
					log.Printf("Selected interface %s with IP %s\n", iface.Name, addr.IP)
					return iface.Name
				}
			}
		}
	}
	preferred := []string{"eth0", "en0", "wlan0", "enp0s1"}
	for _, name := range preferred {
		for _, iface := range interfaces {
			if iface.Name == name {
				log.Printf("Falling back to interface %s\n", name)
				return name
			}
		}
	}
	log.Printf("Using first interface found: %s\n", interfaces[0].Name)
	return interfaces[0].Name
}

func getActiveRootProcesses() []processInfo {
	connections, err := netstat.Connections("inet")
	if err != nil {
		log.Printf("Error getting connections: %v\n", err)
		return []processInfo{{Name: "Error fetching connections: " + err.Error()}}
	}

	rootProcs := make(map[int32]*processInfo)
	seenConns := make(map[string]bool)

	for _, conn := range connections {
		if (conn.Status != "ESTABLISHED" && conn.Status != "LISTEN") || conn.Pid == 0 {
			continue
		}
		proc, err := process.NewProcess(conn.Pid)
		if err != nil {
			log.Printf("Couldn't get process for PID %d: %v\n", conn.Pid, err)
			continue
		}
		name, err := proc.Name()
		if err != nil {
			name = fmt.Sprintf("Unknown (PID: %d)", conn.Pid)
			log.Printf("Couldn't get name for PID %d: %v\n", err)
		}
		connKey := fmt.Sprintf("%d-%s-%d-%s-%d", conn.Pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
		if seenConns[connKey] {
			continue
		}
		seenConns[connKey] = true
		connInfo := connectionInfo{
			LocalIP:    conn.Laddr.IP,
			LocalPort:  conn.Laddr.Port,
			RemoteIP:   conn.Raddr.IP,
			RemotePort: conn.Raddr.Port,
		}
		if info, exists := rootProcs[conn.Pid]; !exists {
			rootProcs[conn.Pid] = &processInfo{
				PID:         conn.Pid,
				Name:        name,
				Connections: []connectionInfo{connInfo},
			}
			log.Printf("Added new process: %s (PID: %d)\n", name, conn.Pid)
		} else {
			info.Connections = append(info.Connections, connInfo)
			log.Printf("Added connection to existing process %s (PID: %d)\n", name, conn.Pid)
		}
	}

	var processes []processInfo
	for _, info := range rootProcs {
		processes = append(processes, *info)
	}
	if len(processes) == 0 {
		log.Println("No active processes found")
		processes = append(processes, processInfo{Name: "No active processes found"})
	}
	sort.Slice(processes, func(i, j int) bool {
		return strings.ToLower(processes[i].Name) < strings.ToLower(processes[j].Name)
	})
	return processes
}

func getConnectionsForPID(pid int32) []connectionInfo {
	connections, err := netstat.Connections("inet")
	if err != nil {
		log.Printf("Error getting connections for PID %d: %v\n", pid, err)
		return nil
	}

	var filteredConnections []netstat.ConnectionStat
	for _, conn := range connections {
		if conn.Pid == pid {
			filteredConnections = append(filteredConnections, conn)
		}
	}
	connections = filteredConnections
	var connInfos []connectionInfo
	for _, conn := range connections {
		if conn.Status != "ESTABLISHED" && conn.Status != "LISTEN" {
			continue
		}
		connInfos = append(connInfos, connectionInfo{
			LocalIP:    conn.Laddr.IP,
			LocalPort:  conn.Laddr.Port,
			RemoteIP:   conn.Raddr.IP,
			RemotePort: conn.Raddr.Port,
		})
		log.Printf("Found connection for PID %d: %s:%d -> %s:%d\n",
			pid, conn.Laddr.IP, conn.Laddr.Port, conn.Raddr.IP, conn.Raddr.Port)
	}
	return connInfos
}

func startCapture(pid int32) {
	activeCapturesMux.Lock()
	if _, exists := activeCaptures[pid]; exists {
		activeCapturesMux.Unlock()
		return
	}
	quitCapture := make(chan bool)
	activeCaptures[pid] = quitCapture
	activeCapturesMux.Unlock()

	iface := getDefaultInterface()
	if iface == "" {
		log.Println("No interface available for capture")
		return
	}

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Printf("Error opening interface: %v\n", err)
		return
	}

	go func() {
		defer handle.Close()
		ticker := time.NewTicker(2 * time.Second)

		data, _ := json.Marshal(map[string]interface{}{
			"type": "monitor_started",
			"pid":  pid,
		})
		log.Printf("Sending monitor_started: %s\n", string(data))
		broadcastToClients(data)

		for {
			connections := getConnectionsForPID(pid)
			log.Printf("Found %d connections for PID %d\n", len(connections), pid)

			var filters []string
			for _, conn := range connections {
				if conn.LocalIP != "" {
					if strings.Contains(conn.LocalIP, ":") {
						filters = append(filters, fmt.Sprintf("src host %s or dst host %s", conn.LocalIP, conn.LocalIP))
					} else {
						filters = append(filters, fmt.Sprintf("ip and (src host %s or dst host %s)", conn.LocalIP, conn.LocalIP))
					}
				}
			}
			bpfFilter := "tcp or udp"
			if len(filters) > 0 {
				bpfFilter = strings.Join(filters, " or ")
			}
			log.Printf("Applying BPF filter: %s\n", bpfFilter)
			if err := handle.SetBPFFilter(bpfFilter); err != nil {
				log.Printf("Failed to set BPF filter: %v\n", err)
				return
			}

			packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
			packetSource.DecodeOptions.Lazy = true
			packetSource.DecodeOptions.NoCopy = true

			for {
				select {
				case <-quitCapture:
					log.Printf("Capture stopped for PID %d\n", pid)
					data, _ := json.Marshal(map[string]interface{}{
						"type": "monitor_stopped",
						"pid":  pid,
					})
					log.Printf("Sending monitor_stopped: %s\n", string(data))
					broadcastToClients(data)
					return
				case <-ticker.C:
					break
				case packet, ok := <-packetSource.Packets():
					if !ok {
						log.Println("Packet channel closed unexpectedly")
						return
					}
					if packet == nil {
						continue
					}
					display := formatPacketForDisplay(packet, pid)
					log.Printf("Captured packet for PID %d: %s\n", pid, display.Summary)
					sharedPacketsMux.Lock()
					sharedPackets[pid] = append(sharedPackets[pid], display)
					if len(sharedPackets[pid]) > 100 {
						sharedPackets[pid] = sharedPackets[pid][len(sharedPackets[pid])-100:]
					}
					sharedPacketsMux.Unlock()
					data, _ := json.Marshal(map[string]interface{}{
						"type": "packet",
						"data": display,
					})
					log.Printf("Sending packet: %s\n", string(data))
					broadcastToClients(data)
				}
				if len(getConnectionsForPID(pid)) != len(connections) {
					break
				}
			}
		}
	}()
}

func stopCapture(pid int32) {
	activeCapturesMux.Lock()
	if quitChan, exists := activeCaptures[pid]; exists {
		quitChan <- true
		delete(activeCaptures, pid)
	}
	activeCapturesMux.Unlock()
}

func formatPacketForDisplay(packet gopacket.Packet, pid int32) packetDisplay {
	var summary, details, hexDump, appData strings.Builder
	metadata := packet.Metadata()

	fmt.Fprintf(&summary, "%s | %5d bytes", metadata.Timestamp.Format("15:04:05.000"), metadata.CaptureLength)
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		fmt.Fprintf(&summary, " | %s", netLayer.LayerType())
	}
	if transportLayer := packet.TransportLayer(); transportLayer != nil {
		fmt.Fprintf(&summary, " | %s", transportLayer.LayerType())
	}
	if netLayer := packet.NetworkLayer(); netLayer != nil {
		flow := netLayer.NetworkFlow()
		fmt.Fprintf(&summary, " | %s → %s", flow.Src(), flow.Dst())
	}

	fmt.Fprintf(&details, "Packet: %d bytes, %s, captured %d/%d @ %s\n",
		len(packet.Data()), ifThen(metadata.CaptureLength < metadata.Length, "truncated", "complete"),
		metadata.CaptureLength, metadata.Length, metadata.Timestamp.Format(time.RFC3339Nano))
	details.WriteString("--------------------------------------------------\n")

	if ethLayer := packet.Layer(layers.LayerTypeEthernet); ethLayer != nil {
		eth, _ := ethLayer.(*layers.Ethernet)
		fmt.Fprintf(&details, "Ethernet | SrcMAC: %-17s | DstMAC: %-17s | Type: %s\n",
			eth.SrcMAC, eth.DstMAC, eth.EthernetType)
	}

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		fmt.Fprintf(&details, "IPv4     | SrcIP: %-15s | DstIP: %-15s | Proto: %s | TTL: %d | Len: %d | Id: %d | Flags: %s\n",
			ip.SrcIP, ip.DstIP, ip.Protocol, ip.TTL, ip.Length, ip.Id, ip.Flags)
	} else if ip6Layer := packet.Layer(layers.LayerTypeIPv6); ip6Layer != nil {
		ip6, _ := ip6Layer.(*layers.IPv6)
		fmt.Fprintf(&details, "IPv6     | SrcIP: %-39s | DstIP: %-39s | Next: %s | HopLimit: %d\n",
			ip6.SrcIP, ip6.DstIP, ip6.NextHeader, ip6.HopLimit)
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		flags := []string{}
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		if tcp.ECE {
			flags = append(flags, "ECE")
		}
		if tcp.CWR {
			flags = append(flags, "CWR")
		}
		if tcp.NS {
			flags = append(flags, "NS")
		}
		fmt.Fprintf(&details, "TCP      | SrcPort: %-5d | DstPort: %-5d | Seq: %-10d | Ack: %-10d | Flags: %s | Win: %d\n",
			tcp.SrcPort, tcp.DstPort, tcp.Seq, tcp.Ack, strings.Join(flags, ","), tcp.Window)
		if len(tcp.Options) > 0 {
			fmt.Fprintf(&details, "         | Options: %v\n", tcp.Options)
		}
	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Fprintf(&details, "UDP      | SrcPort: %-5d | DstPort: %-5d | Length: %d\n",
			udp.SrcPort, udp.DstPort, udp.Length)
	} else if icmpLayer := packet.Layer(layers.LayerTypeICMPv4); icmpLayer != nil {
		icmp, _ := icmpLayer.(*layers.ICMPv4)
		fmt.Fprintf(&details, "ICMP     | Type: %d | Code: %d\n", icmp.TypeCode.Type(), icmp.TypeCode.Code())
	}

	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := appLayer.Payload()
		if len(payload) > 0 {
			fmt.Fprintf(&details, "Payload  | %d bytes\n", len(payload))
			log.Printf("Processing payload for PID %d: %d bytes\n", pid, len(payload))
			if strings.HasPrefix(string(payload), "GET ") || strings.HasPrefix(string(payload), "POST ") ||
				strings.HasPrefix(string(payload), "HTTP/") {
				fmt.Fprintf(&appData, "HTTP Request/Response:\n%s\n", string(payload[:min(512, len(payload))]))
				log.Printf("Detected HTTP payload for PID %d: %s\n", pid, string(payload[:min(64, len(payload))]))
			} else if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
				dns, _ := dnsLayer.(*layers.DNS)
				fmt.Fprintf(&appData, "DNS Query/Response:\n")
				if len(dns.Questions) > 0 {
					fmt.Fprintf(&appData, "Question: %s (Type: %s)\n", dns.Questions[0].Name, dns.Questions[0].Type)
					log.Printf("Detected DNS payload for PID %d: Question %s\n", pid, dns.Questions[0].Name)
				}
				if len(dns.Answers) > 0 {
					fmt.Fprintf(&appData, "Answer: %s\n", dns.Answers[0].String())
					log.Printf("Detected DNS answer for PID %d: %s\n", pid, dns.Answers[0].String())
				}
			} else if isPrintable(string(payload)) {
				fmt.Fprintf(&appData, "Plain Text Data:\n%s\n", string(payload[:min(64, len(payload))]))
				log.Printf("Detected text payload for PID %d: %s\n", pid, string(payload[:min(64, len(payload))]))
			} else {
				fmt.Fprintf(&appData, "Binary Data (non-printable, %d bytes, see hex dump)\n", len(payload))
				log.Printf("Detected binary payload for PID %d: %d bytes\n", pid, len(payload))
			}
		} else {
			fmt.Fprintf(&details, "Payload  | 0 bytes\n")
			log.Printf("No payload for PID %d\n", pid)
		}
	} else {
		fmt.Fprintf(&details, "Payload  | 0 bytes\n")
		log.Printf("No application layer for PID %d\n", pid)
	}

	data := packet.Data()
	for i := 0; i < len(data); i += 16 {
		fmt.Fprintf(&hexDump, "%04x  ", i)
		// Hex bytes
		for j := 0; j < 16 && i+j < len(data); j++ {
			fmt.Fprintf(&hexDump, "%02x ", data[i+j])
		}
		// Pad hex for alignment if less than 16 bytes
		if i+16 > len(data) {
			for j := len(data) - i; j < 16; j++ {
				hexDump.WriteString("   ")
			}
		}
		hexDump.WriteString("  ")
		// ASCII representation
		for j := 0; j < 16 && i+j < len(data); j++ {
			b := data[i+j]
			if b >= 32 && b <= 126 {
				fmt.Fprintf(&hexDump, "%c", b)
			} else {
				hexDump.WriteString(".")
			}
		}
		// Pad ASCII for alignment
		if i+16 > len(data) {
			for j := len(data) - i; j < 16; j++ {
				hexDump.WriteString(" ")
			}
		}
		hexDump.WriteString("\n")
	}

	return packetDisplay{
		Summary:     summary.String(),
		Details:     details.String(),
		HexDump:     hexDump.String(),
		Application: appData.String(),
		PID:         pid,
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func ifThen(condition bool, trueVal, falseVal string) string {
	if condition {
		return trueVal
	}
	return falseVal
}

func isPrintable(s string) bool {
	for _, r := range s {
		if r < 32 || r > 126 {
			return false
		}
	}
	return true
}
