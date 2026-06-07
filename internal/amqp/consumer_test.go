package amqp

import "testing"

func TestConsumerStartValidation(t *testing.T) {
	handler := func(string, string, []byte) {}

	tests := []struct {
		name      string
		consumer  *Consumer
		exchanges []string
	}{
		{
			name:      "missing exchanges",
			consumer:  NewConsumer("amqp://localhost", handler),
			exchanges: nil,
		},
		{
			name:      "empty exchange",
			consumer:  NewConsumer("amqp://localhost", handler),
			exchanges: []string{""},
		},
		{
			name:      "missing handler",
			consumer:  NewConsumer("amqp://localhost", nil),
			exchanges: []string{"miosa.events"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.consumer.Start(tt.exchanges); err == nil {
				t.Fatal("expected validation error")
			}
			tt.consumer.Stop()
			tt.consumer.Stop()
		})
	}
}

func TestParseTelemetryEvent(t *testing.T) {
	event, err := ParseTelemetryEvent([]byte(`{"type":"threat","score":0.9}`))
	if err != nil {
		t.Fatalf("parse telemetry event: %v", err)
	}
	if event["type"] != "threat" {
		t.Fatalf("unexpected event type: %v", event["type"])
	}

	if _, err := ParseTelemetryEvent([]byte(`not-json`)); err == nil {
		t.Fatal("expected invalid JSON error")
	}
}
