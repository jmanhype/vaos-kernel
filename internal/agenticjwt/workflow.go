package agenticjwt

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// WorkflowRegistrationResponse confirms an immutable workflow registration.
type WorkflowRegistrationResponse struct {
	Status     string `json:"status"`
	WorkflowID string `json:"workflow_id"`
}

// UnmarshalJSON accepts the internal ordered-step array and the draft section
// 6.3.3 object shape while preserving step order.
func (d *WorkflowDefinition) UnmarshalJSON(data []byte) error {
	var wire struct {
		WorkflowID string          `json:"workflow_id"`
		Steps      json.RawMessage `json:"steps"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return err
	}
	if len(wire.Steps) == 0 {
		d.WorkflowID = wire.WorkflowID
		d.Steps = nil
		return nil
	}

	trimmed := bytes.TrimSpace(wire.Steps)
	switch trimmed[0] {
	case '[':
		var steps []WorkflowStep
		stepDecoder := json.NewDecoder(bytes.NewReader(trimmed))
		stepDecoder.DisallowUnknownFields()
		if err := stepDecoder.Decode(&steps); err != nil {
			return err
		}
		d.Steps = steps
	case '{':
		object := json.NewDecoder(bytes.NewReader(trimmed))
		object.DisallowUnknownFields()
		if _, err := object.Token(); err != nil {
			return err
		}
		steps := make([]WorkflowStep, 0)
		for object.More() {
			keyToken, err := object.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("workflow step name must be a string")
			}
			var step WorkflowStep
			if err := object.Decode(&step); err != nil {
				return err
			}
			if step.StepID != "" && step.StepID != key {
				return fmt.Errorf("workflow step_id %q does not match object name %q", step.StepID, key)
			}
			step.StepID = key
			steps = append(steps, step)
		}
		if _, err := object.Token(); err != nil {
			return err
		}
		d.WorkflowID = wire.WorkflowID
		d.Steps = steps
	default:
		return fmt.Errorf("workflow steps must be an object or array")
	}
	d.WorkflowID = wire.WorkflowID
	return nil
}
