package agenticjwt

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterWorkflowValidatesDefinitions(t *testing.T) {
	registry := NewRegistry(nil)
	valid := WorkflowDefinition{
		WorkflowID: "patch-workflow",
		Steps: []WorkflowStep{
			{StepID: "analyze", Required: true, AgentID: "analyzer"},
			{StepID: "approval", ApprovalGate: true},
			{StepID: "apply", Required: true, RequiresApproval: true, AgentID: "patcher"},
		},
	}
	if err := registry.RegisterWorkflow("app-one", valid); err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterWorkflow("app-one", valid); !IsCode(err, "invalid_request") {
		t.Fatalf("duplicate workflow error = %v", err)
	}

	tests := []struct {
		name       string
		mutateFunc func(*WorkflowDefinition)
	}{
		{"empty workflow id", func(w *WorkflowDefinition) { w.WorkflowID = "" }},
		{"empty steps", func(w *WorkflowDefinition) { w.Steps = nil }},
		{"empty step id", func(w *WorkflowDefinition) { w.Steps[0].StepID = "" }},
		{"duplicate step", func(w *WorkflowDefinition) { w.Steps[1].StepID = "analyze" }},
		{"approval without prior gate", func(w *WorkflowDefinition) {
			w.Steps = []WorkflowStep{{StepID: "apply", Required: true, RequiresApproval: true}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			definition := valid
			definition.WorkflowID = "invalid-" + strings.ReplaceAll(test.name, " ", "-")
			test.mutateFunc(&definition)
			if err := registry.RegisterWorkflow("app-one", definition); err == nil {
				t.Fatal("accepted invalid workflow")
			}
		})
	}
}

func TestWorkflowDefinitionAcceptsDraftObjectWireShape(t *testing.T) {
	input := `{
		"workflow_id": "object-workflow",
		"steps": {
			"analyze": {"required": true, "agent_id": "supervisor"},
			"approval": {"approval_gate": true},
			"apply": {"required": true, "requires_approval": true, "agent_id": "agent-one"}
		}
	}`
	var definition WorkflowDefinition
	if err := json.Unmarshal([]byte(input), &definition); err != nil {
		t.Fatal(err)
	}
	wantSteps := []string{"analyze", "approval", "apply"}
	if len(definition.Steps) != len(wantSteps) {
		t.Fatalf("steps = %#v", definition.Steps)
	}
	for index, stepID := range wantSteps {
		if definition.Steps[index].StepID != stepID {
			t.Fatalf("step %d = %s, want %s", index, definition.Steps[index].StepID, stepID)
		}
	}
	if err := NewRegistry(nil).RegisterWorkflow("app-one", definition); err != nil {
		t.Fatal(err)
	}
}

func TestWorkflowValidationEnforcesPrerequisitesApprovalAgentAndDelegation(t *testing.T) {
	setup := newTestAuthority(t)
	definition := WorkflowDefinition{
		WorkflowID: "patch-workflow",
		Steps: []WorkflowStep{
			{StepID: "analyze", Required: true, AgentID: "supervisor"},
			{StepID: "approval", ApprovalGate: true},
			{StepID: "apply", Required: true, RequiresApproval: true, AgentID: "agent-one"},
		},
	}
	if err := setup.registry.RegisterWorkflow("app-one", definition); err != nil {
		t.Fatal(err)
	}

	valid := setup.request
	valid.WorkflowID = "patch-workflow"
	valid.WorkflowStep = "apply"
	valid.DelegationContext = &DelegationContext{
		Chain:          []string{"supervisor"},
		CompletedSteps: []string{"analyze", "approval"},
	}
	if _, err := setup.registry.ValidateRequest("app-one", valid); err != nil {
		t.Fatalf("valid workflow request rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*TokenRequest)
	}{
		{"unknown workflow", func(r *TokenRequest) { r.WorkflowID = "missing" }},
		{"unknown step", func(r *TokenRequest) { r.WorkflowStep = "missing" }},
		{"unauthorized agent", func(r *TokenRequest) { r.WorkflowStep = "analyze" }},
		{"missing prerequisite", func(r *TokenRequest) {
			r.DelegationContext.CompletedSteps = []string{"approval"}
		}},
		{"missing approval", func(r *TokenRequest) {
			r.DelegationContext.CompletedSteps = []string{"analyze"}
		}},
		{"out of order", func(r *TokenRequest) {
			r.DelegationContext.CompletedSteps = []string{"approval", "analyze"}
		}},
		{"future step", func(r *TokenRequest) {
			r.DelegationContext.CompletedSteps = []string{"analyze", "approval", "apply"}
		}},
		{"unknown completed step", func(r *TokenRequest) {
			r.DelegationContext.CompletedSteps = []string{"analyze", "approval", "missing"}
		}},
		{"delegation mismatch", func(r *TokenRequest) {
			r.DelegationContext.Chain = []string{"other-agent"}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := valid
			test.mutate(&request)
			_, err := setup.registry.ValidateRequest("app-one", request)
			if !IsCode(err, "workflow_step_unauthorized") {
				t.Fatalf("error = %v, want workflow_step_unauthorized", err)
			}
		})
	}
}

func TestHandleWorkflowRegistration(t *testing.T) {
	setup := newTestAuthority(t)
	workflowRequest := setup.request
	workflowRequest.WorkflowEnabled = true
	workflowRequest.WorkflowID = "patch-workflow"
	workflowRequest.WorkflowStep = "apply"
	workflowRequest.DelegationContext = &DelegationContext{
		Chain:          []string{"supervisor"},
		CompletedSteps: []string{"analyze", "approval"},
	}
	if _, _, err := setup.authority.Mint("app-one", workflowRequest); !IsCode(err, "workflow_step_unauthorized") {
		t.Fatalf("pre-registration error = %v, want workflow_step_unauthorized", err)
	}

	definition := WorkflowDefinition{
		WorkflowID: "patch-workflow",
		Steps: []WorkflowStep{
			{StepID: "analyze", Required: true, AgentID: "supervisor"},
			{StepID: "approval", ApprovalGate: true},
			{StepID: "apply", Required: true, RequiresApproval: true, AgentID: "agent-one"},
		},
	}
	body, err := json.Marshal(definition)
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	setup.authority.HandleWorkflowRegistration(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/intent/register/workflow", strings.NewReader(string(body))),
	)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var response WorkflowRegistrationResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Status != "registered" || response.WorkflowID != definition.WorkflowID {
		t.Fatalf("response = %#v", response)
	}
	if recorder.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("workflow registration response is cacheable")
	}
	if _, _, err := setup.authority.Mint("app-one", workflowRequest); err != nil {
		t.Fatalf("registered workflow rejected: %v", err)
	}

	recorder = httptest.NewRecorder()
	setup.authority.HandleWorkflowRegistration(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/intent/register/workflow", strings.NewReader(string(body))),
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("duplicate status = %d body = %s", recorder.Code, recorder.Body.String())
	}
	var duplicate Error
	if err := json.Unmarshal(recorder.Body.Bytes(), &duplicate); err != nil {
		t.Fatal(err)
	}
	if duplicate.Code != "invalid_request" {
		t.Fatalf("duplicate error = %#v", duplicate)
	}

	invalid := strings.Replace(string(body), `{"workflow_id"`, `{"unexpected":true,"workflow_id"`, 1)
	recorder = httptest.NewRecorder()
	setup.authority.HandleWorkflowRegistration(
		recorder,
		httptest.NewRequest(http.MethodPost, "/v1/intent/register/workflow", strings.NewReader(invalid)),
	)
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("unknown-field status = %d body = %s", recorder.Code, recorder.Body.String())
	}
}
