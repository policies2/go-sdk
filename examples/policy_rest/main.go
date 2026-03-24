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
			Kind:    policysdk.TransportKindREST,
			BaseURL: getenv("POLICY_API_URL", ""),
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
				"scores": map[string]any{
					"theory": map[string]any{
						"multipleChoice":   45,
						"hazardPerception": 75,
					},
					"practical": map[string]any{
						"major": false,
						"minor": 13,
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Policy result:", response.Result)
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
