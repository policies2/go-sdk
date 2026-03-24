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

	response, err := client.ExecuteFlow(context.Background(), policysdk.ExecuteFlowRequest{
		ID:        "ae6fb044-ad2b-45fd-82d1-0d2f1fa176a5",
		Reference: policysdk.ReferenceBase,
		Data: map[string]any{
			"drivingTest": map[string]any{
				"person": map[string]any{
					"name":        "Alice",
					"dateOfBirth": "1992-05-12",
				},
				"scores": map[string]any{
					"theory": map[string]any{
						"multipleChoice":   47,
						"hazardPerception": 70,
					},
					"practical": map[string]any{
						"major": false,
						"minor": 6,
					},
				},
			},
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("Flow result:", string(response.Result))
	fmt.Println("Visited nodes:", len(response.NodeResponse))
}

func getenv(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
