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
			Kind:    policysdk.TransportKindRPC,
			Address: getenv("POLICY_RPC_ADDRESS", "127.0.0.1:8081"),
			TLS:     false,
		},
	})
	if err != nil {
		panic(err)
	}

	response, err := client.ExecutePolicy(context.Background(), policysdk.ExecutePolicyRequest{
		ID:        "3b7d4b2a-9aa0-4b6d-a1b4-9dcf11ce12ab",
		Reference: policysdk.ReferenceBase,
		Data: map[string]any{
			"drivingTest": map[string]any{
				"person": map[string]any{
					"name":        "Bob",
					"dateOfBirth": "1990-01-01",
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Policy result:", response.Result)
	fmt.Println("Execution timing:", response.Execution)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
