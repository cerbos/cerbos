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

func ServeSvcSwagger(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.Body != nil {
			_, _ = io.Copy(io.Discard, r.Body)
			r.Body.Close()
		}
	}()

	schema, err := sjson.SetBytes(svcSwaggerRaw, "info.version", util.Version)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	schema, err = sjson.SetBytes(schema, "host", r.Host)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(schema)
}
