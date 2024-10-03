package core

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"plugin"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/ethereum/go-ethereum/safeguard/etherapi"
)

type safeguardState struct {
	lock    sync.Mutex
	enabled bool
	impl    etherapi.InvariantChecker
}

var safeguardImpl safeguardState

// must be called holding the lock in s
func (s *safeguardState) pause() {
	old := s.enabled
	s.enabled = false
	if s.impl != nil && old {
		s.impl.OnPause()
	}

}

// must be called holding the lock in s
func (s *safeguardState) unpause() {
	s.enabled = true
}

// acquires and releases lock in s
func (s *safeguardState) reload(p string) {
	s.lock.Lock()
	defer s.lock.Unlock()
	plug, err := plugin.Open(p)
	if err != nil {
		fmt.Printf("Failed to load plugin from %s: %s; pausing checking\n", p, err)
		s.pause()
		return
	}
	sym, err := plug.Lookup("Detector")
	if err != nil {
		fmt.Printf("Failed to find detector implementation in %s: %s; pausing checking\n", p, err)
		s.pause()
		return
	}
	impl, ok := sym.(etherapi.InvariantChecker)
	if !ok {
		fmt.Printf("Detector from %p was not an InvariantChecker, pausing checking\n", p)
		s.pause()
		return
	}
	fmt.Printf("Successfully loaded new implementation, updating pointer, and enabling\n")
	s.enabled = true
	s.impl = impl
}

// acquires and releases lock in s
func (s *safeguardState) flipActivate() {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.impl == nil {
		fmt.Printf("Refusing to change status, no plugin loaded\n")
		return
	}
	currentlyEnabled := s.enabled
	if currentlyEnabled {
		s.pause()
	} else {
		s.unpause()
	}
	fmt.Printf("Enabled status changed: %t -> %t\n", currentlyEnabled, s.enabled)
	return
}

// acquires and releases lock in s
func (s *safeguardState) setLogLevel(l slog.Level) {
	s.lock.Lock()
	defer s.lock.Unlock()
	if s.impl == nil {
		fmt.Print("Refusing to set log level: no plugin loaded\n")
		return
	}
	s.impl.SetLogLevel(l)
}

func initSafeguardSignals() {
	fmt.Printf("Setting up signal handlers for process %d\n", os.Getpid())
	signalChan := make(chan os.Signal, 1)
	signal.Notify(signalChan, syscall.SIGUSR2, syscall.SIGUSR1)
	go func(ch chan os.Signal) {
		for s := range ch {
			if s == syscall.SIGUSR1 {
				fmt.Printf("Got request to update checking\n")
				func() {
					p := os.Getenv("SAFEGUARD_PLUGIN_PATH")
					if p == "" {
						fmt.Printf("No safeguard plugin path specified, ignoring load request\n")
						return
					}
					safeguardImpl.reload(p)
				}()
			} else if s == syscall.SIGUSR2 {
				fmt.Printf("Got request to pause/unpause checking\n")
				safeguardImpl.flipActivate()
			} else {
				fmt.Printf("Unexpected signal delivered %s, ignoring\n", s)
			}
		}
	}(signalChan)
}

// Message types
const (
	MessageTypeReload = "RELOAD"
	MessageTypePause  = "PAUSE"
	MessageTypeLog    = "LOG"
	PluginPathEnv     = "SAFEGUARD_PLUGIN_PATH"
	AdminPathEnv      = "SAFEGUARD_SOCKET_PATH"
	SafeguardModeEnv  = "SAFEGUARD_MODE"
	SafeguardPortEnv  = "SAFEGUARD_ADMIN_PORT"
	StartupLoadEnv    = "SAFEGUARD_LOAD_INITIAL"
	AllowReloadFlag   = 0x1
)

// Message struct for IPC
type SafeguardAdminMessage struct {
	Type string `json:"type"`
	Data string `json:"data,omitempty"`
}

// Callback types
type ReloadCallback func(string)
type PauseCallback func()
type SetLogCallback func(string)

// safeguardAdminServer struct
type safeguardAdminServer struct {
	h            adminHandler
	listenPath   string
	socketType   string
	featureFlags int
}

type adminHandler struct {
	reloadCallback ReloadCallback
	pauseCallback  PauseCallback
	setLogCallback SetLogCallback
}

// creates a new IPC server, but does not start it
func newIpcAdminServer(socketPath string, h adminHandler) (*safeguardAdminServer, error) {
	// Clean up the socket if it already exists
	if _, err := os.Stat(socketPath); !os.IsNotExist(err) {
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("failed to remove existing socket @ %s: %w", socketPath, err)
		}
	}
	return &safeguardAdminServer{
		h:            h,
		listenPath:   socketPath,
		socketType:   "unix",
		featureFlags: AllowReloadFlag,
	}, nil
}

// Start begins listening for IPC messages
func (s *safeguardAdminServer) start() error {
	listener, err := net.Listen(s.socketType, s.listenPath)
	if err != nil {
		return fmt.Errorf("failed to listen on socket @ %s: %w", s.listenPath, err)
	}

	go func() {
		defer listener.Close()
		for {
			conn, err := listener.Accept()
			if err != nil {
				fmt.Println("failed to accept connection:", err)
				continue
			}
			go s.handleConnection(conn)
		}
	}()
	return nil
}

const rejectedMessage = "{\"success\": false}"
const acceptedMessage = "{\"success\": true}"

func tryLoadInitial() {
	_, exists := os.LookupEnv(StartupLoadEnv)
	// initial load not requested
	if !exists {
		return
	}
	loadInitial()
}

func loadInitial() {
	p, exists := os.LookupEnv(PluginPathEnv)
	if !exists {
		fmt.Print("Requested initial load, but %s not set, taking no further action\n", PluginPathEnv)
		return
	}
	safeguardImpl.reload(p)
}

// handleConnection processes incoming messages
func (s *safeguardAdminServer) handleConnection(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	for {
		messageBytes, err := reader.ReadBytes('\n')
		if err == io.EOF {
			return
		}
		if err != nil {
			fmt.Println("failed to read message:", err)
			return
		}

		var message SafeguardAdminMessage
		if err := json.Unmarshal(messageBytes, &message); err != nil {
			fmt.Println("failed to unmarshal message:", err)
			continue
		}

		switch message.Type {
		case MessageTypeReload:
			filePath := strings.TrimSpace(message.Data)
			if s.featureFlags&AllowReloadFlag == 0 {
				writer.WriteString(rejectedMessage)
				continue
			}
			s.h.reloadCallback(filePath)
		case MessageTypePause:
			s.h.pauseCallback()
		case MessageTypeLog:
			logLevel := strings.TrimSpace(message.Data)
			s.h.setLogCallback(logLevel)
		default:
			fmt.Println("unknown message type:", message.Type)
			writer.WriteString(rejectedMessage)
			return
		}
		writer.WriteString(acceptedMessage)
	}
}

var stdHandler adminHandler = adminHandler{
	reloadCallback: func(s string) {
		safeguardImpl.reload(s)
	},
	pauseCallback: func() {
		safeguardImpl.flipActivate()
	},
	setLogCallback: func(s string) {
		var p slog.Level
		p.UnmarshalText([]byte(s))
		safeguardImpl.setLogLevel(p)
	},
}

func initSafeguardSocket() {
	socketPath, exists := os.LookupEnv(AdminPathEnv)
	if !exists {
		fmt.Printf("Socket mode requested, but %s not set: taking no further action\n", AdminPathEnv)
		return
	}
	server, err := newIpcAdminServer(socketPath, stdHandler)
	if err != nil {
		fmt.Printf("Error creating server %w: taking no further action\n", err)
		return
	}
	err = server.start()
	if err != nil {
		fmt.Printf("Failed to start server: %w, taking no further action\n", err)
	}
}

func initSafeguardTCP() {
	adminPortStr, exists := os.LookupEnv(SafeguardPortEnv)
	var adminPort int = 6969 // nice
	if exists {
		p, err := strconv.Atoi(adminPortStr)
		if err != nil || p <= 1023 || p > 65335 {
			fmt.Printf("Bad port number \"%s\" in %s, refusing to start server\n", adminPortStr, SafeguardPortEnv)
			return
		}
		adminPort = p
	}
	server := safeguardAdminServer{
		h:            stdHandler,
		listenPath:   fmt.Sprintf(":%d", adminPort),
		socketType:   "tcp",
		featureFlags: AllowReloadFlag,
	}
	err := server.start()
	if err != nil {
		fmt.Printf("Failed to start server: %w, taking no further action\n", err)
	}
}

func init() {
	management, present := os.LookupEnv(SafeguardModeEnv)
	if !present {
		fmt.Printf("%s not set, taking no further action\n", SafeguardModeEnv)
	}
	if management == "SIGNAL" {
		initSafeguardSignals()
		tryLoadInitial()
	} else if management == "SOCKET" {
		initSafeguardSocket()
		tryLoadInitial()
	} else if management == "NET" {
		initSafeguardTCP()
		tryLoadInitial()
	} else if management == "STATIC" {
		loadInitial()
	} else {
		fmt.Printf("Unrecognized safeguard mode: %s, ignoring and taking no further action\n", management)
	}
}
