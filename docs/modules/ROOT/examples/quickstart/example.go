package main

import (
	"context"
	"log"

	cerbos "github.com/cerbos/cerbos/client"
)

func main() {
	c, err := cerbos.New("localhost:3593", cerbos.WithPlaintext())
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	principal := cerbos.NewPrincipal("bugs_bunny", "user")
	principal.WithAttr("beta_tester", true)

	kind := "album:object"
	actions := []string{"view:public", "comment"}

	r1 := cerbos.NewResource(kind, "BUGS001")
	r1.WithAttributes(map[string]any{
		"owner":   "bugs_bunny",
		"public":  false,
		"flagged": false,
	})

	r2 := cerbos.NewResource(kind, "DAFFY002")
	r2.WithAttributes(map[string]any{
		"owner":   "daffy_duck",
		"public":  true,
		"flagged": false,
	})

	batch := cerbos.NewResourceBatch()
	batch.Add(r1, actions...)
	batch.Add(r2, actions...)

	resp, err := c.CheckResources(context.Background(), principal, batch)
	if err != nil {
		log.Fatalf("Failed to check resources: %v", err)
	}
	log.Printf("%v", resp)
}
