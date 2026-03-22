package policysdk

import "encoding/json"

type TransportKind string

const (
	TransportKindREST TransportKind = "rest"
	TransportKindRPC  TransportKind = "rpc"
)

type Reference string

const (
	ReferenceBase    Reference = "base"
	ReferenceVersion Reference = "version"
)

type ExecutePolicyRequest struct {
	ID        string
	Data      map[string]any
	Reference Reference
}

type ExecuteFlowRequest struct {
	ID        string
	Data      map[string]any
	Reference Reference
}

type OrchestratorTiming struct {
	Go       string `json:"go"`
	Database string `json:"database"`
	Total    string `json:"total"`
}

type ExecutionTiming struct {
	Orchestrator *OrchestratorTiming `json:"orchestrator,omitempty"`
	Engine       string              `json:"engine"`
	Total        string              `json:"total"`
}

type PolicyExecutionResult struct {
	Kind      string           `json:"kind"`
	Result    bool             `json:"result"`
	Trace     json.RawMessage  `json:"trace"`
	Rule      []string         `json:"rule"`
	Data      json.RawMessage  `json:"data"`
	Error     json.RawMessage  `json:"error"`
	Errors    json.RawMessage  `json:"errors"`
	Labels    json.RawMessage  `json:"labels"`
	Execution *ExecutionTiming `json:"execution,omitempty"`
	Timings   *ExecutionTiming `json:"timings,omitempty"`
}

type FlowNodeExecution struct {
	Database string `json:"database"`
	Engine   string `json:"engine"`
	Total    string `json:"total"`
}

type FlowNodeResponse struct {
	NodeID    string              `json:"nodeId"`
	NodeType  string              `json:"nodeType"`
	Response  PolicyExecutionData `json:"response"`
	Execution *FlowNodeExecution  `json:"execution,omitempty"`
}

type PolicyExecutionData struct {
	Result bool            `json:"result"`
	Trace  json.RawMessage `json:"trace"`
	Rule   []string        `json:"rule"`
	Data   json.RawMessage `json:"data"`
	Error  json.RawMessage `json:"error"`
	Errors json.RawMessage `json:"errors"`
	Labels json.RawMessage `json:"labels"`
}

type FlowExecutionTiming struct {
	Orchestrator string `json:"orchestrator"`
	Database     string `json:"database"`
	Engine       string `json:"engine"`
	Total        string `json:"total"`
}

type FlowExecutionResult struct {
	Kind         string               `json:"kind"`
	Result       json.RawMessage      `json:"result"`
	NodeResponse []FlowNodeResponse   `json:"nodeResponse"`
	Execution    *FlowExecutionTiming `json:"execution,omitempty"`
	Timings      *FlowExecutionTiming `json:"timings,omitempty"`
}
