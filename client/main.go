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
	"time"

	tea "github.com/charmbracelet/bubbletea"
)

type model struct {
	processes   []processInfo
	selected    int
	viewing     bool
	packets     map[int32][]packetDisplay
	currentPID  int32
	conn        net.Conn
	connStatus  string
	err         string
	debugInfo   []string
	showDetails bool
}

type packetDisplay struct {
	Summary     string `json:"summary"`
	Details     string `json:"details"`
	HexDump     string `json:"hex_dump"`
	Application string `json:"application"`
	Protocol    string `json:"protocol"` 
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

type packetMsg struct {
	pid     int32
	display packetDisplay
}

type tickMsg struct{}

type serverMsg struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

func main() {
	logFile, err := os.OpenFile("netmon-client.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open log file: %v\n", err)
		os.Exit(1)
	}
	log.SetOutput(logFile)
	log.Println("=== Starting Network Monitor Client ===")

	p := tea.NewProgram(initialModel())
	if err := p.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "Error starting application: %v\n", err)
		os.Exit(1)
	}
}

func initialModel() model {
	conn, err := net.Dial("tcp", "localhost:9090")
	connStatus := "Connected"
	if err != nil {
		log.Printf("Failed to connect to server: %v\n", err)
		connStatus = fmt.Sprintf("Failed to connect: %v", err)
	}
	return model{
		processes:   []processInfo{},
		selected:    0,
		viewing:     false,
		packets:     make(map[int32][]packetDisplay),
		currentPID:  0,
		conn:        conn,
		connStatus:  connStatus,
		err:         "",
		debugInfo:   []string{},
		showDetails: false,
	}
}

func (m model) Init() tea.Cmd {
	return tea.Batch(tick(), receiveServerMessages(m.conn))
}

func tick() tea.Cmd {
	return tea.Tick(500*time.Millisecond, func(t time.Time) tea.Msg {
		return tickMsg{}
	})
}

func receiveServerMessages(conn net.Conn) tea.Cmd {
	if conn == nil {
		return nil
	}
	return func() tea.Msg {
		scanner := bufio.NewScanner(conn)
		for scanner.Scan() {
			line := scanner.Text()
			log.Printf("Received message: %s\n", line)
			var msg serverMsg
			if err := json.Unmarshal([]byte(line), &msg); err != nil {
				log.Printf("Failed to parse server message: %v\n", err)
				continue
			}
			switch msg.Type {
			case "processes":
				dataBytes, err := json.Marshal(msg.Data)
				if err != nil {
					log.Printf("Failed to marshal processes data: %v\n", err)
					continue
				}
				var procs []processInfo
				if err := json.Unmarshal(dataBytes, &procs); err != nil {
					log.Printf("Failed to parse processes: %v\n", err)
					continue
				}
				sort.Slice(procs, func(i, j int) bool {
					return strings.ToLower(procs[i].Name) < strings.ToLower(procs[j].Name)
				})
				return serverMsg{Type: "processes", Data: procs}
			case "packet":
				dataBytes, err := json.Marshal(msg.Data)
				if err != nil {
					log.Printf("Failed to marshal packet data: %v\n", err)
					continue
				}
				var pkt packetDisplay
				if err := json.Unmarshal(dataBytes, &pkt); err != nil {
					log.Printf("Failed to parse packet: %v\n", err)
					continue
				}
				if pkt.Application != "" {
					log.Printf("Received packet for PID %d (Protocol: %s): %s\n",
						pkt.PID, pkt.Protocol, pkt.Application[:min(64, len(pkt.Application))])
				}
				return packetMsg{pid: pkt.PID, display: pkt}
			case "monitor_started":
				dataBytes, err := json.Marshal(msg.Data)
				if err != nil {
					log.Printf("Failed to marshal monitor_started data: %v\n", err)
					continue
				}
				var data struct {
					PID int32 `json:"pid"`
				}
				if err := json.Unmarshal(dataBytes, &data); err != nil {
					log.Printf("Failed to parse monitor_started: %v\n", err)
					continue
				}
				return serverMsg{Type: "monitor_started", Data: data}
			case "monitor_stopped":
				dataBytes, err := json.Marshal(msg.Data)
				if err != nil {
					log.Printf("Failed to marshal monitor_stopped data: %v\n", err)
					continue
				}
				var data struct {
					PID int32 `json:"pid"`
				}
				if err := json.Unmarshal(dataBytes, &data); err != nil {
					log.Printf("Failed to parse monitor_stopped: %v\n", err)
					continue
				}
				return serverMsg{Type: "monitor_stopped", Data: data}
			}
		}
		if err := scanner.Err(); err != nil {
			log.Printf("Server connection error: %v\n", err)
			return serverMsg{Type: "connection_error"}
		}
		return nil
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q":
			if m.viewing {
				log.Println("User exited capture view")
				if m.conn != nil {
					data, _ := json.Marshal(map[string]interface{}{
						"type": "stop_monitor",
						"pid":  m.currentPID,
					})
					fmt.Fprintf(m.conn, "%s\n", data)
				}
				m.viewing = false
				m.currentPID = 0
				m.debugInfo = []string{}
				m.packets[m.currentPID] = nil
				m.selected = 0
				return m, nil
			}
			log.Println("User quit application")
			if m.conn != nil {
				m.conn.Close()
			}
			return m, tea.Quit
		case "up":
			if m.selected > 0 && !m.viewing {
				m.selected--
				log.Printf("Selected process %d: %s\n", m.selected, m.processes[m.selected].Name)
			}
		case "down":
			if m.selected < len(m.processes)-1 && !m.viewing {
				m.selected++
				log.Printf("Selected process %d: %s\n", m.selected, m.processes[m.selected].Name)
			}
		case "enter":
			if !m.viewing && len(m.processes) > 0 && m.processes[m.selected].PID != 0 && m.conn != nil {
				log.Printf("User selected process %s (PID: %d)\n",
					m.processes[m.selected].Name, m.processes[m.selected].PID)
				m.viewing = true
				m.currentPID = m.processes[m.selected].PID
				m.debugInfo = []string{"Waiting for packets..."}
				data, _ := json.Marshal(map[string]interface{}{
					"type": "start_monitor",
					"pid":  m.currentPID,
				})
				fmt.Fprintf(m.conn, "%s\n", data)
				return m, tick()
			}
		case "r":
			if m.viewing {
				log.Println("User refreshed capture")
				if m.conn != nil {
					data, _ := json.Marshal(map[string]interface{}{
						"type": "stop_monitor",
						"pid":  m.currentPID,
					})
					fmt.Fprintf(m.conn, "%s\n", data)
					data, _ = json.Marshal(map[string]interface{}{
						"type": "start_monitor",
						"pid":  m.currentPID,
					})
					fmt.Fprintf(m.conn, "%s\n", data)
				}
				m.debugInfo = []string{"Refreshing capture..."}
				m.packets[m.currentPID] = nil
				return m, tick()
			}
		case "d":
			if m.viewing {
				m.showDetails = !m.showDetails
				log.Printf("Toggled details view: %v\n", m.showDetails)
			}
		}
	case packetMsg:
		if m.viewing && m.currentPID == msg.pid {
			m.packets[msg.pid] = append(m.packets[msg.pid], msg.display)
			if len(m.packets[msg.pid]) > 100 {
				m.packets[msg.pid] = m.packets[msg.pid][len(m.packets[msg.pid])-100:]
			}
			log.Printf("Added packet to UI for PID %d, total: %d\n", msg.pid, len(m.packets[msg.pid]))
		}
	case serverMsg:
		switch msg.Type {
		case "processes":
			procs, ok := msg.Data.([]processInfo)
			if !ok {
				log.Println("Failed to cast processes data to []processInfo")
				return m, receiveServerMessages(m.conn)
			}
			m.processes = procs
			log.Printf("Received %d processes\n", len(procs))
		case "monitor_started":
			data, ok := msg.Data.(struct {
				PID int32 `json:"pid"`
			})
			if !ok {
				log.Println("Failed to cast monitor_started data")
			} else {
				log.Printf("Monitor started for PID %d\n", data.PID)
			}
		case "monitor_stopped":
			data, ok := msg.Data.(struct {
				PID int32 `json:"pid"`
			})
			if !ok {
				log.Println("Failed to cast monitor_stopped data")
			} else if m.viewing && m.currentPID == data.PID {
				log.Printf("Monitor stopped for PID %d\n", data.PID)
				m.viewing = false
				m.currentPID = 0
				m.debugInfo = []string{}
				m.packets[data.PID] = nil
				m.selected = 0
			}
		case "connection_error":
			m.connStatus = "Disconnected"
			if m.conn != nil {
				m.conn.Close()
				m.conn = nil
			}
			return m, nil
		}
	case tickMsg:
		if m.viewing {
			if len(m.debugInfo) > 10 {
				m.debugInfo = m.debugInfo[1:]
			}
			return m, tick()
		}
	}
	return m, receiveServerMessages(m.conn)
}

func (m model) View() string {
	var b strings.Builder

	if m.err != "" {
		b.WriteString(fmt.Sprintf("\033[1;31mError: %s\033[0m\n", m.err))
		return b.String()
	}

	b.WriteString(fmt.Sprintf("\033[1;36mConnection Status: %s\033[0m\n\n", m.connStatus))

	if m.viewing {
		b.WriteString(fmt.Sprintf("\033[1;34mNetwork Activity for %s (PID: %d)\033[0m\n\n",
			getProcessName(m.processes, m.currentPID), m.currentPID))

		if len(m.debugInfo) > 0 {
			b.WriteString("\033[1;33m[Debug Info]\033[0m\n")
			for _, msg := range m.debugInfo {
				b.WriteString(fmt.Sprintf("- %s\n", msg))
			}
			b.WriteString("\n")
		}

		packets := m.packets[m.currentPID]
		if len(packets) == 0 {
			b.WriteString("\033[1;33mWaiting for packets...\033[0m\n")
			b.WriteString("• Packets should appear here shortly\n")
			b.WriteString("• Check netmon-client.log for details\n")
		} else {
			b.WriteString(fmt.Sprintf("\033[1;32mCaptured %d packets (Press 'd' to toggle details):\033[0m\n\n", len(packets)))
			for i, pkt := range packets {
				b.WriteString(fmt.Sprintf("\033[1;36mPacket %d (Protocol: %s):\033[0m\n", i+1, pkt.Protocol))
				b.WriteString(pkt.Summary + "\n")
				if m.showDetails {
					b.WriteString(pkt.Details)
					if pkt.Application != "" {
						b.WriteString("Application Data:\n")
						b.WriteString(pkt.Application)
					}
					b.WriteString("Hex Dump:\n")
					b.WriteString(pkt.HexDump)
				}
				b.WriteString("\n")
			}
		}
		b.WriteString("\n\033[1;36mControls: d=Toggle Details | r=Refresh | q=Back\033[0m\n")
	} else {
		b.WriteString("\033[1;32mActive Network Processes:\033[0m\n\n")
		for i, proc := range m.processes {
			cursor := "  "
			if m.selected == i {
				cursor = "\033[1;33m>>\033[0m"
			}
			connStr := "No connections"
			if len(proc.Connections) > 0 {
				conn := proc.Connections[0]
				connStr = fmt.Sprintf("Local: %s:%d | Remote: %s:%d",
					conn.LocalIP, conn.LocalPort, conn.RemoteIP, conn.RemotePort)
				if len(proc.Connections) > 1 {
					connStr += fmt.Sprintf(" (+%d more)", len(proc.Connections)-1)
				}
			}
			b.WriteString(fmt.Sprintf("%s %-20s | PID: %-6d | %s\n",
				cursor, proc.Name, proc.PID, connStr))
		}
		b.WriteString("\n\033[1;36mControls: ↑/↓=Navigate | Enter=View Packets | q=Quit\033[0m")
	}
	return b.String()
}

func getProcessName(processes []processInfo, pid int32) string {
	for _, proc := range processes {
		if proc.PID == pid {
			return proc.Name
		}
	}
	return fmt.Sprintf("PID: %d", pid)
}
