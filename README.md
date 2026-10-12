# `github.com/policies2/go-sdk`

Execute stored policies and flows over REST or gRPC using API keys only.

This SDK mirrors the narrow scope of the TypeScript package:

- execute policies
- execute flows
- authenticate with `x-api-key`
- choose REST or gRPC transport

It does not support creating, updating, publishing, or administering resources.

## Install

```bash
go get github.com/policies2/go-sdk
```

## Usage

```go
package main

import (
	"context"
	"fmt"
	"os"

	policysdk "github.com/policies2/go-sdk"
)

func main() {
	client, err := policysdk.NewExecutionClient(policysdk.Config{
		APIKey: os.Getenv("POLICY_API_KEY"),
		Transport: policysdk.TransportConfig{
			Kind: policysdk.TransportKindREST,
		},
	})
	if err != nil {
		panic(err)
	}

	result, err := client.ExecutePolicy(context.Background(), policysdk.ExecutePolicyRequest{
		ID:        "3b7d4b2a-9aa0-4b6d-a1b4-9dcf11ce12ab",
		Reference: policysdk.ReferenceBase,
		Data: map[string]any{
			"user": map[string]any{"age": 25},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.Result)
}
```

REST defaults to `https://api.policy2.net/run` when `Transport.BaseURL` is empty.

gRPC (`TransportKindRPC`) has no hosted endpoint yet, so `Transport.Address` is required. The SDK refuses plaintext gRPC to anything but a loopback address (`localhost`, `127.0.0.1`, `::1`), because the API key travels in request metadata: set `Transport.TLS: true` for any remote server.

## Examples

- REST policy execution: [`examples/policy_rest/main.go`](./examples/policy_rest/main.go)
- REST flow execution: [`examples/flow_rest/main.go`](./examples/flow_rest/main.go)
- RPC policy execution: [`examples/policy_rpc/main.go`](./examples/policy_rpc/main.go)
- RPC flow execution: [`examples/flow_rpc/main.go`](./examples/flow_rpc/main.go)
