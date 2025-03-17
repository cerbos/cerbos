package main

import (
	"context"
	"log"

	"github.com/cerbos/cerbos-sdk-go/cerbos"
)

func main() {
	c, err := cerbos.New("localhost:3593", cerbos.WithPlaintext())
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	principal := cerbos.NewPrincipal("123", "USER")
	// We use map[string]any as strictly typed nested maps aren't supported
	principal.WithAttr("workspaces", map[string]map[string]any{
		"workspaceA": {
			"role": "OWNER",
		},
		"workspaceB": {
			"role": "MEMBER",
		},
	})

	kind := "workspace"
	actions := []string{"workspace:view", "pii:view"}

	batch := cerbos.NewResourceBatch()
	batch.Add(cerbos.NewResource(kind, "workspaceA"), actions...)
	batch.Add(cerbos.NewResource(kind, "workspaceB"), actions...)

	resp, err := c.CheckResources(context.Background(), principal, batch)
	if err != nil {
		log.Fatalf("Failed to check resources: %v", err)
	}
	log.Printf("%v", resp)
}
