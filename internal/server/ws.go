package server

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/websocket"
)

// Hub maintains the set of active WebSocket clients and broadcasts messages.
type Hub struct {
	mu         sync.RWMutex
	clients    map[*Client]struct{}
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
}

// Client represents a single WebSocket connection.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
}

// NewHub creates a new Hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]struct{}),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run processes register, unregister, and broadcast events. Should be called
// as a goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = struct{}{}
			h.mu.Unlock()

		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					go func(c *Client) {
						h.unregister <- c
					}(client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// Broadcast serialises data as JSON and sends it to every connected client.
func (h *Hub) Broadcast(data any) {
	msg, err := json.Marshal(data)
	if err != nil {
		log.Printf("ws: broadcast marshal error: %v", err)
		return
	}
	h.broadcast <- msg
}

// ServeWs upgrades an HTTP connection to WebSocket and registers the client
// with the hub. checkOrigin must allow only trusted Vaultify UI origins.
func (h *Hub) ServeWs(w http.ResponseWriter, r *http.Request, checkOrigin func(*http.Request) bool) {
	upgrader := websocket.Upgrader{
		CheckOrigin: checkOrigin,
	}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws: upgrade error: %v", err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}
	h.register <- client

	go client.writePump()
	go client.readPump()
}

func (srv *Server) handleScanWebSocket(w http.ResponseWriter, r *http.Request) {
	srv.hub.ServeWs(w, r, srv.wsCheckOrigin)
}

func (srv *Server) wsCheckOrigin(r *http.Request) bool {
	o := strings.TrimSpace(r.Header.Get("Origin"))
	if o == "" {
		return true
	}
	port := srv.listenPort
	if port == 0 {
		port = 9471
	}
	return o == fmt.Sprintf("http://127.0.0.1:%d", port) || o == fmt.Sprintf("http://localhost:%d", port)
}

// readPump reads messages from the WebSocket connection. When the connection
// closes it unregisters the client.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()
	for {
		if _, _, err := c.conn.ReadMessage(); err != nil {
			break
		}
	}
}

// writePump sends queued messages to the WebSocket connection.
func (c *Client) writePump() {
	defer c.conn.Close()
	for msg := range c.send {
		if err := c.conn.WriteMessage(websocket.TextMessage, msg); err != nil {
			break
		}
	}
}
