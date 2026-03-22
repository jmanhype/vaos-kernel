package websocket

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"vaos-kernel/internal/nhi"
	"vaos-kernel/pkg/models"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type Server struct {
	registry *nhi.Registry
	clients  map[string]*Client
	mu       sync.RWMutex
}

type Client struct {
	ID   string
	Conn *websocket.Conn
	Send  chan []byte
	mu    sync.Mutex
}

func NewServer(registry *nhi.Registry) *Server {
	server := &Server{
		registry: registry,
		clients:  make(map[string]*Client),
	}

	// Subscribe to registry state change notifications
	registry.OnStateChange(server.handleAgentStateChange)

	return server
}

func (s *Server) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade error: %v", err)
		return
	}

	clientID := generateClientID()
	client := &Client{
		ID:   clientID,
		Conn: conn,
		Send:  make(chan []byte, 256),
	}

	s.mu.Lock()
	s.clients[clientID] = client
	s.mu.Unlock()

	// Start write pump first so we can send through the channel
	go s.writePump(client)

	// Send welcome through the writePump channel to avoid concurrent writes
	welcome := map[string]interface{}{
		"type": "connection",
		"payload": map[string]interface{}{
			"status":   "connected",
			"client_id": clientID,
		},
	}
	welcomeData, _ := json.Marshal(welcome)
	select {
	case client.Send <- welcomeData:
	default:
	}

	// Auto-send agent list on connect
	s.handleListAgents(client)

	go s.readPump(client)
}

func (s *Server) readPump(client *Client) {
	defer func() {
		s.unregisterClient(client)
		client.Conn.Close()
	}()

	for {
		_, message, err := client.Conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("WebSocket error: %v", err)
			}
			break
		}

		s.handleMessage(client, message)
	}
}

func (s *Server) writePump(client *Client) {
	ticker := time.NewTicker(54 * time.Second)
	defer func() {
		ticker.Stop()
		client.Conn.Close()
	}()

	for {
		select {
		case message, ok := <-client.Send:
			if !ok {
				client.Conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			if err := client.Conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("WebSocket write error: %v", err)
				return
			}

		case <-ticker.C:
			ping := map[string]interface{}{"type": "ping"}
			data, _ := json.Marshal(ping)
			if err := client.Conn.WriteMessage(websocket.PingMessage, data); err != nil {
				return
			}
		}
	}
}

func (s *Server) handleMessage(client *Client, data []byte) {
	var msg map[string]interface{}
	if err := json.Unmarshal(data, &msg); err != nil {
		log.Printf("Failed to parse message: %v", err)
		return
	}

	msgType, ok := msg["type"].(string)
	if !ok {
		log.Printf("Message missing type field")
		return
	}

	switch msgType {
	case "get_agent":
		s.handleGetAgent(client, msg)
	case "list_agents":
		s.handleListAgents(client)
	case "send_command", "command":
		s.handleSendCommand(client, msg)
	case "subscribe":
		s.handleSubscribe(client, msg)
	case "unsubscribe":
		s.handleUnsubscribe(client, msg)
	case "pong":
		// Ignore pong messages
	default:
		log.Printf("Unknown message type: %s", msgType)
	}
}

func (s *Server) handleGetAgent(client *Client, msg map[string]interface{}) {
	payload, ok := msg["payload"].(map[string]interface{})
	if !ok {
		s.sendError(client, "Invalid payload")
		return
	}

	agentID, ok := payload["agent_id"].(string)
	if !ok {
		s.sendError(client, "Missing agent_id")
		return
	}

	agent, err := s.registry.GetAgent(agentID)
	if err != nil {
		s.sendError(client, fmt.Sprintf("Agent not found: %v", err))
		return
	}

	agentInfo := map[string]interface{}{
		"id":              agent.ID,
		"name":            agent.Name,
		"roles":           agent.Roles,
		"capabilities":     agent.Capabilities,
		"reputation_score": agent.ReputationScore,
		"metadata":        agent.Metadata,
	}

	s.sendMessage(client, map[string]interface{}{
		"type": "agent_state",
		"payload": map[string]interface{}{
			"agent_id": agentID,
			"agent_info": agentInfo,
		},
	})
}

func (s *Server) handleListAgents(client *Client) {
	agents := s.registry.ListAll()

	agentInfos := make([]map[string]interface{}, len(agents))
	for i, agent := range agents {
		agentInfos[i] = map[string]interface{}{
			"id":              agent.ID,
			"name":            agent.Name,
			"persona":         agent.Persona,
			"state":           int(agent.State),
			"roles":           agent.Roles,
			"capabilities":     agent.Capabilities,
			"reputation_score": agent.ReputationScore,
			"metadata":        agent.Metadata,
		}
	}

	s.sendMessage(client, map[string]interface{}{
		"type": "list_agents",
		"payload": map[string]interface{}{
			"agents": agentInfos,
		},
	})
}

func (s *Server) handleSendCommand(client *Client, msg map[string]interface{}) {
	payload, ok := msg["payload"].(map[string]interface{})
	if !ok {
		s.sendError(client, "Invalid payload")
		return
	}

	agentID, _ := payload["agent_id"].(string)
	command, _ := payload["command"].(string)
	params := make(map[string]interface{})
	if p, ok := payload["parameters"].(map[string]interface{}); ok {
		params = p
	}

	s.sendMessage(client, map[string]interface{}{
		"type": "command_response",
		"payload": map[string]interface{}{
			"success":  true,
			"agent_id":  agentID,
			"command":   command,
			"parameters": params,
		},
	})
}

func (s *Server) handleSubscribe(client *Client, msg map[string]interface{}) {
	payload, ok := msg["payload"].(map[string]interface{})
	if !ok {
		s.sendError(client, "Invalid payload")
		return
	}

	agentID, ok := payload["agent_id"].(string)
	if !ok {
		s.sendError(client, "Missing agent_id")
		return
	}

	s.sendMessage(client, map[string]interface{}{
		"type": "subscribed",
		"payload": map[string]interface{}{
			"agent_id": agentID,
		},
	})
}

func (s *Server) handleUnsubscribe(client *Client, msg map[string]interface{}) {
	payload, ok := msg["payload"].(map[string]interface{})
	if !ok {
		s.sendError(client, "Invalid payload")
		return
	}

	agentID, ok := payload["agent_id"].(string)
	if !ok {
		s.sendError(client, "Missing agent_id")
		return
	}

	s.sendMessage(client, map[string]interface{}{
		"type": "unsubscribed",
		"payload": map[string]interface{}{
			"agent_id": agentID,
		},
	})
}

func (s *Server) unregisterClient(client *Client) {
	s.mu.Lock()
	delete(s.clients, client.ID)
	s.mu.Unlock()

	close(client.Send)
}

func (s *Server) sendMessage(client *Client, msg map[string]interface{}) {
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("Failed to marshal message: %v", err)
		return
	}

	select {
	case client.Send <- data:
	default:
		log.Printf("Client send channel full, dropping message")
	}
}

func (s *Server) sendError(client *Client, message string) {
	s.sendMessage(client, map[string]interface{}{
		"type": "error",
		"payload": map[string]interface{}{
			"error": message,
		},
	})
}

func (s *Server) BroadcastTelemetry(agentID string, telemetry map[string]interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, client := range s.clients {
		s.sendMessage(client, map[string]interface{}{
			"type": "telemetry",
			"payload": map[string]interface{}{
				"agent_id":  agentID,
				"timestamp": time.Now().Unix(),
				"data":      telemetry,
			},
		})
	}
}

func generateClientID() string {
	return fmt.Sprintf("client-%d-%d", time.Now().Unix(), time.Now().UnixNano()%1000)
}

func (s *Server) handleAgentStateChange(agentID string, oldState, newState models.AgentState) {
	agent, err := s.registry.GetAgent(agentID)
	if err != nil {
		log.Printf("Failed to get agent for state change: %v", err)
		return
	}

	// Broadcast state update to all connected clients
	s.mu.RLock()
	defer s.mu.RUnlock()

	agentInfo := map[string]interface{}{
		"id":              agent.ID,
		"name":            agent.Name,
		"persona":         agent.Persona,
		"state":           int(agent.State),
		"roles":           agent.Roles,
		"capabilities":     agent.Capabilities,
		"reputation_score": agent.ReputationScore,
		"metadata":        agent.Metadata,
		"last_active":     agent.LastActive.Unix(),
	}

	for _, client := range s.clients {
		s.sendMessage(client, map[string]interface{}{
			"type": "state_update",
			"payload": agentInfo,
		})
	}
}

// BroadcastEvent forwards an AMQP event to all connected WebSocket clients.
// Used by the Kernel's AMQP consumer to proxy Swarm telemetry to the Interface.
func (s *Server) BroadcastEvent(exchange, routingKey string, event map[string]interface{}) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	// Determine event type based on exchange
	eventType := "telemetry"
	if routingKey == "threat" || routingKey == "security" {
		eventType = "threat"
	}

	for _, client := range s.clients {
		s.sendMessage(client, map[string]interface{}{
			"type": eventType,
			"payload": map[string]interface{}{
				"exchange":    exchange,
				"routing_key": routingKey,
				"data":        event,
			},
		})
	}
}
