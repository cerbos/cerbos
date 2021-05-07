// Copyright 2021 Zenauth Ltd.

package schema

import (

	// signal to the compiler that files need to be embedded.
	_ "embed"
	"io"
	"net/http"

	"github.com/tidwall/sjson"

	"github.com/cerbos/cerbos/internal/util"
)

//go:embed openapiv2/svc/v1/svc.swagger.json
var svcSwaggerRaw []byte

//go:embed assets/ui.html
var rapidocHTML []byte

func ServeSvcSwagger(w http.ResponseWriter, r *http.Request) {
	defer cleanup(r)

	httpScheme := "http"
	if r.TLS != nil {
		httpScheme = "https"
	}

	schema, err := newSwaggerMod().setVersion(util.Version).setHost(r.Host).setScheme(httpScheme).build()
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(schema)
}

func ServeUI(w http.ResponseWriter, r *http.Request) {
	defer cleanup(r)

	_, _ = w.Write(rapidocHTML)
}

func cleanup(r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(io.Discard, r.Body)
		r.Body.Close()
	}
}

type swaggerMod struct {
	schema []byte
	err    error
}

func newSwaggerMod() *swaggerMod {
	return &swaggerMod{
		schema: svcSwaggerRaw,
	}
}

func (sm *swaggerMod) setVersion(version string) *swaggerMod {
	if sm.err == nil {
		sm.schema, sm.err = sjson.SetBytes(sm.schema, "info.version", version)
	}

	return sm
}

func (sm *swaggerMod) setHost(host string) *swaggerMod {
	if sm.err == nil {
		sm.schema, sm.err = sjson.SetBytes(sm.schema, "host", host)
	}

	return sm
}

func (sm *swaggerMod) setScheme(scheme string) *swaggerMod {
	if sm.err == nil {
		sm.schema, sm.err = sjson.SetBytes(sm.schema, "schemes.0", scheme)
	}

	return sm
}

func (sm *swaggerMod) build() ([]byte, error) {
	return sm.schema, sm.err
}
