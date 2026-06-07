package amqp

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	amqp "github.com/rabbitmq/amqp091-go"
)

// EventHandler is called for each AMQP message received.
type EventHandler func(exchangeName string, routingKey string, body []byte)

var errConsumerStopped = errors.New("amqp consumer is stopped")

// Consumer subscribes to AMQP exchanges and forwards events.
type Consumer struct {
	url     string
	handler EventHandler

	mu        sync.RWMutex
	lifecycle sync.RWMutex
	conn      *amqp.Connection
	channel   *amqp.Channel
	exchanges []string

	done     chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
	started  int32
}

type subscription struct {
	exchange   string
	deliveries <-chan amqp.Delivery
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
	c.lifecycle.RLock()
	defer c.lifecycle.RUnlock()

	if len(exchanges) == 0 {
		return errors.New("start amqp consumer: at least one exchange is required")
	}
	for _, exchange := range exchanges {
		if exchange == "" {
			return errors.New("start amqp consumer: exchange name is required")
		}
	}
	if c.handler == nil {
		return errors.New("start amqp consumer: event handler is required")
	}
	if !atomic.CompareAndSwapInt32(&c.started, 0, 1) {
		return errors.New("start amqp consumer: already started")
	}

	c.mu.Lock()
	c.exchanges = append([]string(nil), exchanges...)
	c.mu.Unlock()

	if err := c.connect(exchanges); err != nil {
		atomic.StoreInt32(&c.started, 0)
		return err
	}

	c.wg.Add(1)
	go c.monitor()
	return nil
}

func (c *Consumer) connect(exchanges []string) error {
	select {
	case <-c.done:
		return errConsumerStopped
	default:
	}

	conn, err := amqp.Dial(c.url)
	if err != nil {
		return fmt.Errorf("dial RabbitMQ: %w", err)
	}

	channel, err := conn.Channel()
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("open RabbitMQ channel: %w", err)
	}

	subscriptions := make([]subscription, 0, len(exchanges))
	for _, exchange := range exchanges {
		if exchange == "" {
			_ = channel.Close()
			_ = conn.Close()
			return errors.New("subscribe RabbitMQ exchange: exchange name is required")
		}
		if err := channel.ExchangeDeclare(
			exchange,
			"topic",
			true,
			false,
			false,
			false,
			nil,
		); err != nil {
			_ = channel.Close()
			_ = conn.Close()
			return fmt.Errorf("declare exchange %s: %w", exchange, err)
		}

		q, err := channel.QueueDeclare("", false, true, true, false, nil)
		if err != nil {
			_ = channel.Close()
			_ = conn.Close()
			return fmt.Errorf("declare queue for %s: %w", exchange, err)
		}
		if err := channel.QueueBind(q.Name, "#", exchange, false, nil); err != nil {
			_ = channel.Close()
			_ = conn.Close()
			return fmt.Errorf("bind queue to %s: %w", exchange, err)
		}
		deliveries, err := channel.Consume(q.Name, "", true, true, false, false, nil)
		if err != nil {
			_ = channel.Close()
			_ = conn.Close()
			return fmt.Errorf("consume from %s: %w", exchange, err)
		}
		subscriptions = append(subscriptions, subscription{
			exchange:   exchange,
			deliveries: deliveries,
		})
	}

	select {
	case <-c.done:
		_ = channel.Close()
		_ = conn.Close()
		return errConsumerStopped
	default:
	}

	c.mu.Lock()
	c.conn = conn
	c.channel = channel
	c.mu.Unlock()

	for _, sub := range subscriptions {
		log.Printf("[AMQP] Subscribed to exchange: %s", sub.exchange)
		c.wg.Add(1)
		go c.consume(sub)
	}
	return nil
}

func (c *Consumer) consume(sub subscription) {
	defer c.wg.Done()
	for {
		select {
		case <-c.done:
			return
		case msg, ok := <-sub.deliveries:
			if !ok {
				return
			}
			c.handler(sub.exchange, msg.RoutingKey, msg.Body)
		}
	}
}

func (c *Consumer) monitor() {
	defer c.wg.Done()

	for {
		c.mu.RLock()
		conn := c.conn
		exchanges := append([]string(nil), c.exchanges...)
		c.mu.RUnlock()
		if conn == nil {
			return
		}

		notifyClose := conn.NotifyClose(make(chan *amqp.Error, 1))
		select {
		case <-c.done:
			return
		case closeErr := <-notifyClose:
			select {
			case <-c.done:
				return
			default:
			}
			if closeErr != nil {
				log.Printf("[AMQP] Connection lost: %v", closeErr)
			} else {
				log.Printf("[AMQP] Connection closed")
			}
		}

		for {
			select {
			case <-c.done:
				return
			case <-time.After(5 * time.Second):
			}

			c.lifecycle.RLock()
			err := c.connect(exchanges)
			c.lifecycle.RUnlock()
			if err != nil {
				log.Printf("[AMQP] Reconnect failed: %v", err)
				continue
			}
			log.Printf("[AMQP] Reconnected")
			break
		}
	}
}

// Stop closes the AMQP connection and waits for consumer goroutines.
func (c *Consumer) Stop() {
	c.stopOnce.Do(func() {
		c.lifecycle.Lock()
		close(c.done)
		c.mu.RLock()
		channel := c.channel
		conn := c.conn
		c.mu.RUnlock()
		if channel != nil {
			_ = channel.Close()
		}
		if conn != nil {
			_ = conn.Close()
		}
		c.lifecycle.Unlock()
		c.wg.Wait()
	})
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
