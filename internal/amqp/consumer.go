package amqp

import (
	"encoding/json"
	"log"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// EventHandler is called for each AMQP message received.
type EventHandler func(exchangeName string, routingKey string, body []byte)

// Consumer subscribes to AMQP exchanges and forwards events.
type Consumer struct {
	url      string
	conn     *amqp.Connection
	channel  *amqp.Channel
	handler  EventHandler
	done     chan struct{}
}

// NewConsumer creates an AMQP consumer that connects to RabbitMQ.
func NewConsumer(url string, handler EventHandler) *Consumer {
	return &Consumer{
		url:     url,
		handler: handler,
		done:    make(chan struct{}),
	}
}

// Start connects to RabbitMQ and begins consuming from the specified exchanges.
func (c *Consumer) Start(exchanges []string) error {
	var err error
	c.conn, err = amqp.Dial(c.url)
	if err != nil {
		return err
	}

	c.channel, err = c.conn.Channel()
	if err != nil {
		return err
	}

	for _, exchange := range exchanges {
		// Declare a temporary queue for this consumer
		q, err := c.channel.QueueDeclare(
			"",    // auto-generated name
			false, // non-durable
			true,  // auto-delete when consumer disconnects
			true,  // exclusive
			false,
			nil,
		)
		if err != nil {
			log.Printf("[AMQP] Failed to declare queue for %s: %v", exchange, err)
			continue
		}

		// Bind to the exchange with wildcard routing key
		err = c.channel.QueueBind(q.Name, "#", exchange, false, nil)
		if err != nil {
			log.Printf("[AMQP] Failed to bind queue to %s: %v", exchange, err)
			continue
		}

		// Start consuming
		msgs, err := c.channel.Consume(q.Name, "", true, true, false, false, nil)
		if err != nil {
			log.Printf("[AMQP] Failed to consume from %s: %v", exchange, err)
			continue
		}

		log.Printf("[AMQP] Subscribed to exchange: %s", exchange)

		go func(ex string, deliveries <-chan amqp.Delivery) {
			for msg := range deliveries {
				c.handler(ex, msg.RoutingKey, msg.Body)
			}
		}(exchange, msgs)
	}

	// Monitor connection
	go func() {
		connClose := c.conn.NotifyClose(make(chan *amqp.Error))
		select {
		case err := <-connClose:
			if err != nil {
				log.Printf("[AMQP] Connection lost: %v, reconnecting in 5s...", err)
				time.Sleep(5 * time.Second)
				c.Start(exchanges)
			}
		case <-c.done:
			return
		}
	}()

	return nil
}

// Stop closes the AMQP connection.
func (c *Consumer) Stop() {
	close(c.done)
	if c.channel != nil {
		c.channel.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

// ParseTelemetryEvent attempts to parse an AMQP message as a telemetry event
// and returns it as a map suitable for WebSocket forwarding.
func ParseTelemetryEvent(body []byte) (map[string]interface{}, error) {
	var event map[string]interface{}
	if err := json.Unmarshal(body, &event); err != nil {
		return nil, err
	}
	return event, nil
}
