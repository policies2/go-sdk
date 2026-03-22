package policysdk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestNewExecutionClientRequiresAPIKey(t *testing.T) {
	_, err := NewExecutionClient(Config{
		APIKey: "",
		Transport: TransportConfig{
			Kind:    TransportKindREST,
			BaseURL: "https://api.policy2.net",
		},
	})
	if err == nil {
		t.Fatal("expected configuration error")
	}

	sdkErr, ok := err.(*Error)
	if !ok || sdkErr.Kind != ErrorKindConfiguration {
		t.Fatalf("expected configuration error, got %#v", err)
	}
}

func TestExecutePolicyRESTVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/run/policy_version/policy-123" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "pk_test" {
			t.Fatalf("unexpected api key header %q", r.Header.Get("X-API-Key"))
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}
		if string(body) != `{"data":{"user":{"age":25}}}` {
			t.Fatalf("unexpected request body %s", string(body))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":true,"trace":null,"rule":["rule"],"data":{"user":{"age":25}},"error":null,"labels":null}`))
	}))
	defer server.Close()

	client, err := NewExecutionClient(Config{
		APIKey: "pk_test",
		Transport: TransportConfig{
			Kind:    TransportKindREST,
			BaseURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	response, err := client.ExecutePolicy(context.Background(), ExecutePolicyRequest{
		ID:        "policy-123",
		Reference: ReferenceVersion,
		Data:      map[string]any{"user": map[string]any{"age": 25}},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if response.Kind != "policy" || !response.Result {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestExecuteFlowRESTBase(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/run/flow/flow-123" {
			t.Fatalf("unexpected path %q", r.URL.Path)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"result":{"approved":true},"nodeResponse":[{"nodeId":"node-1","nodeType":"policy","response":{"result":true,"trace":null,"rule":["rule"],"data":{"approved":true},"error":null,"labels":null}}]}`))
	}))
	defer server.Close()

	client, err := NewExecutionClient(Config{
		APIKey: "pk_test",
		Transport: TransportConfig{
			Kind:    TransportKindREST,
			BaseURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	response, err := client.ExecuteFlow(context.Background(), ExecuteFlowRequest{
		ID:        "flow-123",
		Reference: ReferenceBase,
		Data:      map[string]any{"user": map[string]any{"age": 25}},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}

	if response.Kind != "flow" || len(response.NodeResponse) != 1 || response.NodeResponse[0].NodeID != "node-1" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestRESTErrorMapping(t *testing.T) {
	testCases := []struct {
		name       string
		status     int
		body       string
		wantKind   ErrorKind
		wantStatus int
	}{
		{name: "401", status: http.StatusUnauthorized, body: "bad key", wantKind: ErrorKindAuthentication, wantStatus: 401},
		{name: "403", status: http.StatusForbidden, body: "forbidden", wantKind: ErrorKindAuthorization, wantStatus: 403},
		{name: "500", status: http.StatusInternalServerError, body: "boom", wantKind: ErrorKindServer, wantStatus: 500},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, tc.body, tc.status)
			}))
			defer server.Close()

			client, err := NewExecutionClient(Config{
				APIKey: "pk_test",
				Transport: TransportConfig{
					Kind:    TransportKindREST,
					BaseURL: server.URL,
				},
			})
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			_, err = client.ExecutePolicy(context.Background(), ExecutePolicyRequest{ID: "policy-123", Data: map[string]any{}})
			if err == nil {
				t.Fatal("expected error")
			}
			sdkErr, ok := err.(*Error)
			if !ok {
				t.Fatalf("expected sdk error, got %#v", err)
			}
			if sdkErr.Kind != tc.wantKind || sdkErr.StatusCode != tc.wantStatus {
				t.Fatalf("unexpected error %#v", sdkErr)
			}
		})
	}
}

func TestRESTInvalidJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("{"))
	}))
	defer server.Close()

	client, err := NewExecutionClient(Config{
		APIKey: "pk_test",
		Transport: TransportConfig{
			Kind:    TransportKindREST,
			BaseURL: server.URL,
		},
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	_, err = client.ExecutePolicy(context.Background(), ExecutePolicyRequest{ID: "policy-123", Data: map[string]any{}})
	if err == nil {
		t.Fatal("expected error")
	}
	sdkErr, ok := err.(*Error)
	if !ok || sdkErr.Kind != ErrorKindTransport {
		t.Fatalf("unexpected error %#v", err)
	}
}

func TestExecutePolicyRPCBase(t *testing.T) {
	runPolicyDesc, runResponseDesc, err := rpcPolicyDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}
	runFlowDesc, flowResponseDesc, err := rpcFlowDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}

	server, address := startGRPCTestServer(t, runPolicyDesc, runFlowDesc, runResponseDesc, flowResponseDesc, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		if method != "RunPolicy" {
			t.Fatalf("unexpected method %s", method)
		}
		md, ok := metadata.FromIncomingContext(ctx)
		if !ok || len(md.Get("x-api-key")) == 0 || md.Get("x-api-key")[0] != "pk_test" {
			t.Fatalf("missing api key metadata: %#v", md)
		}
		encoded, err := protojson.Marshal(req)
		if err != nil {
			t.Fatalf("failed to marshal request: %v", err)
		}
		var payload map[string]any
		if err := json.Unmarshal(encoded, &payload); err != nil {
			t.Fatalf("failed to decode request payload: %v", err)
		}
		if payload["baseId"] != "base-123" {
			t.Fatalf("unexpected baseId %#v", payload["baseId"])
		}
		data, ok := payload["data"].(map[string]any)
		if !ok {
			t.Fatalf("unexpected data payload %#v", payload["data"])
		}
		user, ok := data["user"].(map[string]any)
		if !ok || user["age"] != float64(25) {
			t.Fatalf("unexpected user payload %#v", data["user"])
		}

		response := dynamicpb.NewMessage(runResponseDesc)
		response.Set(runResponseDesc.Fields().ByName("result"), protoreflect.ValueOfBool(true))
		response.Set(runResponseDesc.Fields().ByName("data"), protoreflect.ValueOfMessage(mustStruct(t, map[string]any{"approved": true}).ProtoReflect()))
		return response, nil
	})
	defer server.Stop()

	client, err := NewExecutionClient(Config{
		APIKey: "pk_test",
		Transport: TransportConfig{
			Kind:    TransportKindRPC,
			Address: address,
		},
		Timeout: time.Second * 5,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	response, err := client.ExecutePolicy(context.Background(), ExecutePolicyRequest{
		ID:        "base-123",
		Reference: ReferenceBase,
		Data:      map[string]any{"user": map[string]any{"age": 25}},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if !response.Result || response.Kind != "policy" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestExecuteFlowRPCVersion(t *testing.T) {
	_, runFlowDesc, _, flowResponseDesc, err := rpcMessageDescriptorsWithResponses()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}
	runPolicyDesc, runResponseDesc, err := rpcPolicyDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}

	server, address := startGRPCTestServer(t, runPolicyDesc, runFlowDesc, runResponseDesc, flowResponseDesc, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
		if method != "RunFlow" {
			t.Fatalf("unexpected method %s", method)
		}
		msg := req.(*dynamicpb.Message)
		if got := msg.Get(runFlowDesc.Fields().ByName("flow_id")).String(); got != "flow-123" {
			t.Fatalf("unexpected flow_id %q", got)
		}

		response := dynamicpb.NewMessage(flowResponseDesc)
		value, _ := structpb.NewValue(map[string]any{"approved": true})
		response.Set(flowResponseDesc.Fields().ByName("result"), protoreflect.ValueOfMessage(value.ProtoReflect()))
		return response, nil
	})
	defer server.Stop()

	client, err := NewExecutionClient(Config{
		APIKey: "pk_test",
		Transport: TransportConfig{
			Kind:    TransportKindRPC,
			Address: address,
		},
		Timeout: time.Second * 5,
	})
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	response, err := client.ExecuteFlow(context.Background(), ExecuteFlowRequest{
		ID:   "flow-123",
		Data: map[string]any{"user": map[string]any{"age": 25}},
	})
	if err != nil {
		t.Fatalf("expected success, got %v", err)
	}
	if response.Kind != "flow" {
		t.Fatalf("unexpected response %#v", response)
	}
}

func TestRPCErrorMapping(t *testing.T) {
	runPolicyDesc, runResponseDesc, err := rpcPolicyDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}
	runFlowDesc, flowResponseDesc, err := rpcFlowDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}

	testCases := []struct {
		name     string
		status   error
		wantKind ErrorKind
	}{
		{name: "unauthenticated", status: status.Error(codes.Unauthenticated, "bad key"), wantKind: ErrorKindAuthentication},
		{name: "permission denied", status: status.Error(codes.PermissionDenied, "forbidden"), wantKind: ErrorKindAuthorization},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			server, address := startGRPCTestServer(t, runPolicyDesc, runFlowDesc, runResponseDesc, flowResponseDesc, func(ctx context.Context, method string, req proto.Message) (proto.Message, error) {
				return nil, tc.status
			})
			defer server.Stop()

			client, err := NewExecutionClient(Config{
				APIKey: "pk_test",
				Transport: TransportConfig{
					Kind:    TransportKindRPC,
					Address: address,
				},
				Timeout: time.Second * 5,
			})
			if err != nil {
				t.Fatalf("failed to create client: %v", err)
			}

			_, err = client.ExecutePolicy(context.Background(), ExecutePolicyRequest{ID: "policy-123", Data: map[string]any{}})
			if err == nil {
				t.Fatal("expected error")
			}
			sdkErr, ok := err.(*Error)
			if !ok || sdkErr.Kind != tc.wantKind {
				t.Fatalf("unexpected error %#v", err)
			}
		})
	}
}

func startGRPCTestServer(t *testing.T, runPolicyDesc, runFlowDesc, runResponseDesc, flowResponseDesc protoreflect.MessageDescriptor, handler func(context.Context, string, proto.Message) (proto.Message, error)) (*grpc.Server, string) {
	t.Helper()

	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	server := grpc.NewServer()
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "policy.v1.PolicyService",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "RunPolicy",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					req := dynamicpb.NewMessage(runPolicyDesc)
					if err := dec(req); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return handler(ctx, "RunPolicy", req)
					}
					info := &grpc.UnaryServerInfo{FullMethod: policyServiceMethod}
					return interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
						return handler(ctx, "RunPolicy", req.(proto.Message))
					})
				},
			},
		},
	}, struct{}{})
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "policy.v1.FlowService",
		HandlerType: (*interface{})(nil),
		Methods: []grpc.MethodDesc{
			{
				MethodName: "RunFlow",
				Handler: func(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
					req := dynamicpb.NewMessage(runFlowDesc)
					if err := dec(req); err != nil {
						return nil, err
					}
					if interceptor == nil {
						return handler(ctx, "RunFlow", req)
					}
					info := &grpc.UnaryServerInfo{FullMethod: flowServiceMethod}
					return interceptor(ctx, req, info, func(ctx context.Context, req interface{}) (interface{}, error) {
						return handler(ctx, "RunFlow", req.(proto.Message))
					})
				},
			},
		},
	}, struct{}{})

	go func() {
		_ = server.Serve(lis)
	}()

	return server, lis.Addr().String()
}

func mustStruct(t *testing.T, value map[string]any) *structpb.Struct {
	t.Helper()
	result, err := structpb.NewStruct(value)
	if err != nil {
		t.Fatalf("failed to build struct: %v", err)
	}
	return result
}

func TestPathHelpers(t *testing.T) {
	if got := policyPath("base-123", ReferenceBase); got != "/run/policy/base-123" {
		t.Fatalf("unexpected policy path %s", got)
	}
	if got := flowPath("flow-123", ReferenceVersion); got != "/run/flow_version/flow-123" {
		t.Fatalf("unexpected flow path %s", got)
	}
}

func TestDecodeRPCResponses(t *testing.T) {
	runPolicyDesc, runResponseDesc, err := rpcPolicyDescriptors()
	if err != nil {
		t.Fatalf("failed to load descriptors: %v", err)
	}
	if runPolicyDesc == nil {
		t.Fatal("expected policy descriptor")
	}

	runResponse := dynamicpb.NewMessage(runResponseDesc)
	runResponse.Set(runResponseDesc.Fields().ByName("result"), protoreflect.ValueOfBool(true))
	runResponse.Set(runResponseDesc.Fields().ByName("error"), protoreflect.ValueOfMessage(mustStruct(t, map[string]any{"message": "none"}).ProtoReflect()))

	decoded, err := decodePolicyResponse(runResponse)
	if err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !decoded.Result || decoded.Kind != "policy" {
		t.Fatalf("unexpected decoded response %#v", decoded)
	}

	_, flowResponseDesc, err := rpcFlowDescriptors()
	if err != nil {
		t.Fatalf("failed to load flow descriptors: %v", err)
	}
	flowResponse := dynamicpb.NewMessage(flowResponseDesc)
	value, _ := structpb.NewValue("ok")
	flowResponse.Set(flowResponseDesc.Fields().ByName("result"), protoreflect.ValueOfMessage(value.ProtoReflect()))

	decodedFlow, err := decodeFlowResponse(flowResponse)
	if err != nil {
		t.Fatalf("failed to decode flow response: %v", err)
	}
	var result string
	if err := json.Unmarshal(decodedFlow.Result, &result); err != nil {
		t.Fatalf("failed to unmarshal flow result: %v", err)
	}
	if result != "ok" || decodedFlow.Kind != "flow" {
		t.Fatalf("unexpected decoded flow response %#v", decodedFlow)
	}
}

func TestMapHTTPErrorDefaultsMessage(t *testing.T) {
	err := mapHTTPError(500, "")
	sdkErr, ok := err.(*Error)
	if !ok {
		t.Fatalf("expected sdk error, got %#v", err)
	}
	if sdkErr.Message != fmt.Sprintf("request failed with status %d", 500) {
		t.Fatalf("unexpected message %q", sdkErr.Message)
	}
}
