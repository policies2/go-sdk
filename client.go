package policysdk

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	grpcstatus "google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/structpb"
)

const defaultTimeout = 30 * time.Second

const (
	defaultRESTRunBaseURL = "https://api.policy2.net/run"
	defaultRPCAddress     = "shuttle.proxy.rlwy.net:27179"

	policyServiceMethod = "/policy.v1.PolicyService/RunPolicy"
	flowServiceMethod   = "/policy.v1.FlowService/RunFlow"
)

type RestTransportConfig struct {
	BaseURL string
	Client  *http.Client
}

type RPCTransportConfig struct {
	Address string
	TLS     bool
}

type TransportConfig struct {
	Kind    TransportKind
	BaseURL string
	Address string
	TLS     bool
	Client  *http.Client
}

type Config struct {
	APIKey    string
	Transport TransportConfig
	Timeout   time.Duration
	UserAgent string
}

type ExecutionClient struct {
	transport TransportKind
	apiKey    string
	baseURL   string
	client    *http.Client
	address   string
	useTLS    bool
	conn      *grpc.ClientConn
	timeout   time.Duration
	userAgent string
}

func NewExecutionClient(cfg Config) (*ExecutionClient, error) {
	if strings.TrimSpace(cfg.APIKey) == "" {
		return nil, &Error{Kind: ErrorKindConfiguration, Message: "api key is required"}
	}

	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	kind := cfg.Transport.Kind
	if kind == "" {
		kind = TransportKindREST
	}

	client := &ExecutionClient{
		transport: kind,
		apiKey:    cfg.APIKey,
		timeout:   timeout,
		userAgent: cfg.UserAgent,
	}

	switch kind {
	case TransportKindREST:
		httpClient := cfg.Transport.Client
		if httpClient == nil {
			httpClient = &http.Client{Timeout: timeout}
		}
		baseURL := strings.TrimSpace(cfg.Transport.BaseURL)
		if baseURL == "" {
			baseURL = defaultRESTRunBaseURL
		}
		client.baseURL = strings.TrimRight(baseURL, "/")
		client.client = httpClient
	case TransportKindRPC:
		address := strings.TrimSpace(cfg.Transport.Address)
		if address == "" {
			address = defaultRPCAddress
		}
		client.address = address
		client.useTLS = cfg.Transport.TLS
	default:
		return nil, &Error{Kind: ErrorKindConfiguration, Message: fmt.Sprintf("unsupported transport kind %q", kind)}
	}

	return client, nil
}

func (c *ExecutionClient) ExecutePolicy(ctx context.Context, req ExecutePolicyRequest) (*PolicyExecutionResult, error) {
	switch c.transport {
	case TransportKindREST:
		path := policyPath(req.ID, req.Reference)
		var out PolicyExecutionResult
		if err := c.sendREST(ctx, path, req.Data, &out); err != nil {
			return nil, err
		}
		out.Kind = "policy"
		return &out, nil
	case TransportKindRPC:
		return c.executePolicyRPC(ctx, req)
	default:
		return nil, &Error{Kind: ErrorKindConfiguration, Message: fmt.Sprintf("unsupported transport kind %q", c.transport)}
	}
}

func (c *ExecutionClient) ExecuteFlow(ctx context.Context, req ExecuteFlowRequest) (*FlowExecutionResult, error) {
	switch c.transport {
	case TransportKindREST:
		path := flowPath(req.ID, req.Reference)
		var out FlowExecutionResult
		if err := c.sendREST(ctx, path, req.Data, &out); err != nil {
			return nil, err
		}
		out.Kind = "flow"
		return &out, nil
	case TransportKindRPC:
		return c.executeFlowRPC(ctx, req)
	default:
		return nil, &Error{Kind: ErrorKindConfiguration, Message: fmt.Sprintf("unsupported transport kind %q", c.transport)}
	}
}

func (c *ExecutionClient) sendREST(ctx context.Context, path string, data map[string]any, out any) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	body, err := json.Marshal(map[string]any{"data": data})
	if err != nil {
		return &Error{Kind: ErrorKindTransport, Message: "failed to encode request body", Cause: err}
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(body))
	if err != nil {
		return &Error{Kind: ErrorKindTransport, Message: "failed to create request", Cause: err}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-API-Key", c.apiKey)
	if c.userAgent != "" {
		httpReq.Header.Set("User-Agent", c.userAgent)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return &Error{Kind: ErrorKindTransport, Message: "rest execution request failed", Cause: err}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return &Error{Kind: ErrorKindTransport, Message: "failed to read response body", Cause: err}
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return mapHTTPError(resp.StatusCode, string(respBody))
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return &Error{Kind: ErrorKindTransport, Message: "failed to decode response body", Cause: err}
	}

	return nil
}

func (c *ExecutionClient) executePolicyRPC(ctx context.Context, req ExecutePolicyRequest) (*PolicyExecutionResult, error) {
	runPolicyDesc, runResponseDesc, err := rpcPolicyDescriptors()
	if err != nil {
		return nil, err
	}

	request := dynamicpb.NewMessage(runPolicyDesc)
	if effectiveReference(req.Reference) == ReferenceBase {
		request.Set(runPolicyDesc.Fields().ByName("base_id"), protoreflect.ValueOfString(req.ID))
	} else {
		request.Set(runPolicyDesc.Fields().ByName("policy_id"), protoreflect.ValueOfString(req.ID))
	}
	dataStruct, err := structpb.NewStruct(req.Data)
	if err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to encode rpc request data", Cause: err}
	}
	request.Set(runPolicyDesc.Fields().ByName("data"), protoreflect.ValueOfMessage(dataStruct.ProtoReflect()))

	response := dynamicpb.NewMessage(runResponseDesc)
	if err := c.invokeRPC(ctx, policyServiceMethod, request, response); err != nil {
		return nil, err
	}

	return decodePolicyResponse(response)
}

func (c *ExecutionClient) executeFlowRPC(ctx context.Context, req ExecuteFlowRequest) (*FlowExecutionResult, error) {
	runFlowDesc, flowResponseDesc, err := rpcFlowDescriptors()
	if err != nil {
		return nil, err
	}

	request := dynamicpb.NewMessage(runFlowDesc)
	if effectiveReference(req.Reference) == ReferenceBase {
		request.Set(runFlowDesc.Fields().ByName("base_id"), protoreflect.ValueOfString(req.ID))
	} else {
		request.Set(runFlowDesc.Fields().ByName("flow_id"), protoreflect.ValueOfString(req.ID))
	}
	dataStruct, err := structpb.NewStruct(req.Data)
	if err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to encode rpc request data", Cause: err}
	}
	request.Set(runFlowDesc.Fields().ByName("data"), protoreflect.ValueOfMessage(dataStruct.ProtoReflect()))

	response := dynamicpb.NewMessage(flowResponseDesc)
	if err := c.invokeRPC(ctx, flowServiceMethod, request, response); err != nil {
		return nil, err
	}

	return decodeFlowResponse(response)
}

func (c *ExecutionClient) invokeRPC(ctx context.Context, method string, request, response proto.Message) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.timeout)
		defer cancel()
	}

	conn, err := c.rpcConn(ctx)
	if err != nil {
		return err
	}

	ctx = metadata.AppendToOutgoingContext(ctx, "x-api-key", c.apiKey)
	if err := conn.Invoke(ctx, method, request, response); err != nil {
		return mapRPCError(err)
	}

	return nil
}

func mapRPCError(err error) error {
	if err == nil {
		return nil
	}

	statusErr, ok := grpcstatus.FromError(err)
	if !ok {
		return &Error{Kind: ErrorKindTransport, Message: "rpc execution request failed", Cause: err}
	}

	switch statusErr.Code() {
	case codes.Unauthenticated:
		return &Error{Kind: ErrorKindAuthentication, Message: statusErr.Message(), Cause: err}
	case codes.PermissionDenied:
		return &Error{Kind: ErrorKindAuthorization, Message: statusErr.Message(), Cause: err}
	default:
		return &Error{Kind: ErrorKindTransport, Message: "rpc execution request failed", Cause: err}
	}
}

func (c *ExecutionClient) rpcConn(ctx context.Context) (*grpc.ClientConn, error) {
	if c.conn != nil {
		return c.conn, nil
	}

	var creds credentials.TransportCredentials
	if c.useTLS {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	} else {
		creds = insecure.NewCredentials()
	}

	conn, err := grpc.DialContext(ctx, c.address, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to connect to rpc endpoint", Cause: err}
	}

	c.conn = conn
	return conn, nil
}

func policyPath(id string, ref Reference) string {
	if effectiveReference(ref) == ReferenceVersion {
		return fmt.Sprintf("/policy_version/%s", id)
	}
	return fmt.Sprintf("/policy/%s", id)
}

func flowPath(id string, ref Reference) string {
	if effectiveReference(ref) == ReferenceVersion {
		return fmt.Sprintf("/flow_version/%s", id)
	}
	return fmt.Sprintf("/flow/%s", id)
}

func effectiveReference(ref Reference) Reference {
	if ref == ReferenceVersion {
		return ReferenceVersion
	}
	return ReferenceBase
}

func mapHTTPError(status int, body string) error {
	message := strings.TrimSpace(body)
	if message == "" {
		message = fmt.Sprintf("request failed with status %d", status)
	}

	switch status {
	case http.StatusUnauthorized:
		return &Error{Kind: ErrorKindAuthentication, Message: message, StatusCode: status}
	case http.StatusForbidden:
		return &Error{Kind: ErrorKindAuthorization, Message: message, StatusCode: status}
	default:
		return &Error{Kind: ErrorKindServer, Message: message, StatusCode: status}
	}
}

func decodePolicyResponse(message proto.Message) (*PolicyExecutionResult, error) {
	data, err := protojson.Marshal(message)
	if err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to decode rpc policy response", Cause: err}
	}

	var out PolicyExecutionResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to unmarshal rpc policy response", Cause: err}
	}
	out.Kind = "policy"
	return &out, nil
}

func decodeFlowResponse(message proto.Message) (*FlowExecutionResult, error) {
	data, err := protojson.Marshal(message)
	if err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to decode rpc flow response", Cause: err}
	}

	var out FlowExecutionResult
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, &Error{Kind: ErrorKindTransport, Message: "failed to unmarshal rpc flow response", Cause: err}
	}
	out.Kind = "flow"
	return &out, nil
}

func rpcMessageDescriptorsWithResponses() (runPolicy, runFlow, runResponse, flowResponse protoreflect.MessageDescriptor, err error) {
	file, err := protodesc.NewFile(policyFileDescriptorProto(), protoregistry.GlobalFiles)
	if err != nil {
		return nil, nil, nil, nil, &Error{Kind: ErrorKindTransport, Message: "failed to build rpc descriptors", Cause: err}
	}

	messages := file.Messages()
	runPolicy = messages.ByName("RunPolicyRequest")
	runFlow = messages.ByName("RunFlowRequest")
	runResponse = messages.ByName("RunResponse")
	flowResponse = messages.ByName("FlowResponse")
	if runPolicy == nil || runFlow == nil || runResponse == nil || flowResponse == nil {
		return nil, nil, nil, nil, &Error{Kind: ErrorKindTransport, Message: "missing rpc descriptors"}
	}
	return runPolicy, runFlow, runResponse, flowResponse, nil
}

func rpcPolicyDescriptors() (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, error) {
	runPolicy, _, runResponse, _, err := rpcMessageDescriptorsWithResponses()
	return runPolicy, runResponse, err
}

func rpcFlowDescriptors() (protoreflect.MessageDescriptor, protoreflect.MessageDescriptor, error) {
	_, runFlow, _, flowResponse, err := rpcMessageDescriptorsWithResponses()
	return runFlow, flowResponse, err
}

func policyFileDescriptorProto() *descriptorpb.FileDescriptorProto {
	optional := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL
	repeated := descriptorpb.FieldDescriptorProto_LABEL_REPEATED
	stringType := descriptorpb.FieldDescriptorProto_TYPE_STRING
	boolType := descriptorpb.FieldDescriptorProto_TYPE_BOOL
	messageType := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE

	return &descriptorpb.FileDescriptorProto{
		Name:    proto.String("policy_rpc.proto"),
		Package: proto.String("policy.v1"),
		Syntax:  proto.String("proto3"),
		Dependency: []string{
			"google/protobuf/struct.proto",
		},
		MessageType: []*descriptorpb.DescriptorProto{
			{
				Name: proto.String("RunPolicyRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("policy_id"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("policyId")},
					{Name: proto.String("data"), Number: proto.Int32(2), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("data")},
					{Name: proto.String("base_id"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("baseId")},
				},
			},
			{
				Name: proto.String("RunFlowRequest"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("flow_id"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("flowId")},
					{Name: proto.String("data"), Number: proto.Int32(2), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("data")},
					{Name: proto.String("base_id"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("baseId")},
				},
			},
			{
				Name: proto.String("RunResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("result"), Number: proto.Int32(1), Label: &optional, Type: &boolType, JsonName: proto.String("result")},
					{Name: proto.String("trace"), Number: proto.Int32(2), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("trace")},
					{Name: proto.String("rule"), Number: proto.Int32(3), Label: &repeated, Type: &stringType, JsonName: proto.String("rule")},
					{Name: proto.String("data"), Number: proto.Int32(4), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("data")},
					{Name: proto.String("error"), Number: proto.Int32(5), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("error")},
					{Name: proto.String("labels"), Number: proto.Int32(6), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Struct"), JsonName: proto.String("labels")},
					{Name: proto.String("execution"), Number: proto.Int32(7), Label: &optional, Type: &messageType, TypeName: proto.String(".policy.v1.ExecutionTiming"), JsonName: proto.String("execution")},
				},
			},
			{
				Name: proto.String("ExecutionTiming"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("orchestrator"), Number: proto.Int32(1), Label: &optional, Type: &messageType, TypeName: proto.String(".policy.v1.OrchestratorTiming"), JsonName: proto.String("orchestrator")},
					{Name: proto.String("engine"), Number: proto.Int32(2), Label: &optional, Type: &stringType, JsonName: proto.String("engine")},
					{Name: proto.String("total"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("total")},
				},
			},
			{
				Name: proto.String("OrchestratorTiming"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("go"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("go")},
					{Name: proto.String("database"), Number: proto.Int32(2), Label: &optional, Type: &stringType, JsonName: proto.String("database")},
					{Name: proto.String("total"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("total")},
				},
			},
			{
				Name: proto.String("FlowResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("result"), Number: proto.Int32(1), Label: &optional, Type: &messageType, TypeName: proto.String(".google.protobuf.Value"), JsonName: proto.String("result")},
					{Name: proto.String("node_response"), Number: proto.Int32(2), Label: &repeated, Type: &messageType, TypeName: proto.String(".policy.v1.FlowNodeResponse"), JsonName: proto.String("nodeResponse")},
					{Name: proto.String("execution"), Number: proto.Int32(3), Label: &optional, Type: &messageType, TypeName: proto.String(".policy.v1.FlowExecutionTiming"), JsonName: proto.String("execution")},
				},
			},
			{
				Name: proto.String("FlowNodeResponse"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("node_id"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("nodeId")},
					{Name: proto.String("node_type"), Number: proto.Int32(2), Label: &optional, Type: &stringType, JsonName: proto.String("nodeType")},
					{Name: proto.String("response"), Number: proto.Int32(3), Label: &optional, Type: &messageType, TypeName: proto.String(".policy.v1.RunResponse"), JsonName: proto.String("response")},
					{Name: proto.String("execution"), Number: proto.Int32(4), Label: &optional, Type: &messageType, TypeName: proto.String(".policy.v1.FlowNodeExecution"), JsonName: proto.String("execution")},
				},
			},
			{
				Name: proto.String("FlowNodeExecution"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("database"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("database")},
					{Name: proto.String("engine"), Number: proto.Int32(2), Label: &optional, Type: &stringType, JsonName: proto.String("engine")},
					{Name: proto.String("total"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("total")},
				},
			},
			{
				Name: proto.String("FlowExecutionTiming"),
				Field: []*descriptorpb.FieldDescriptorProto{
					{Name: proto.String("orchestrator"), Number: proto.Int32(1), Label: &optional, Type: &stringType, JsonName: proto.String("orchestrator")},
					{Name: proto.String("database"), Number: proto.Int32(2), Label: &optional, Type: &stringType, JsonName: proto.String("database")},
					{Name: proto.String("engine"), Number: proto.Int32(3), Label: &optional, Type: &stringType, JsonName: proto.String("engine")},
					{Name: proto.String("total"), Number: proto.Int32(4), Label: &optional, Type: &stringType, JsonName: proto.String("total")},
				},
			},
		},
	}
}
