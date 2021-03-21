package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	"github.com/cerbos/cerbos/pkg/engine"
	policyv1 "github.com/cerbos/cerbos/pkg/generated/policy/v1"
	requestv1 "github.com/cerbos/cerbos/pkg/generated/request/v1"
	responsev1 "github.com/cerbos/cerbos/pkg/generated/response/v1"
	sharedv1 "github.com/cerbos/cerbos/pkg/generated/shared/v1"
	"github.com/cerbos/cerbos/pkg/namer"
	"github.com/cerbos/cerbos/pkg/policy"
	"github.com/cerbos/cerbos/pkg/storage"
)

const maxRequestSize = 1024 * 1024 // 1 MiB

type Server struct {
	log   *zap.SugaredLogger
	eng   *engine.Engine
	store storage.Store
}

func New(eng *engine.Engine, store storage.Store) *Server {
	return &Server{
		log:   zap.S().Named("http.server"),
		eng:   eng,
		store: store,
	}
}

func (s *Server) Handler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/check", s.handleCheck).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/v1/admin/policy", s.handleAdminPolicy).Methods(http.MethodPost, http.MethodPut, http.MethodDelete)

	return r
}

func cleanup(r *http.Request) {
	if r.Body != nil {
		_, _ = io.Copy(ioutil.Discard, r.Body)
		r.Body.Close()
	}
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	defer cleanup(r)

	log := s.log.Named("check")

	reqBytes, err := ioutil.ReadAll(&io.LimitedReader{R: r.Body, N: maxRequestSize})
	if err != nil {
		log.Errorw("Failed to read request body", "error", err)
		writeResponse(log, w, "unknown", http.StatusBadRequest, "Bad request", sharedv1.Effect_EFFECT_DENY)

		return
	}

	req := &requestv1.Request{}
	if err := protojson.Unmarshal(reqBytes, req); err != nil {
		log.Errorw("Failed to unmarshal request body", "error", err)
		writeResponse(log, w, "unknown", http.StatusBadRequest, "Bad request", sharedv1.Effect_EFFECT_DENY)

		return
	}

	if err := req.Validate(); err != nil {
		log.Errorw("Validation failed for request", "error", err)
		writeResponse(log, w, req.RequestId, http.StatusBadRequest, fmt.Sprintf("Invalid request: %v", err), sharedv1.Effect_EFFECT_DENY)

		return
	}

	log = log.With("request_id", req.RequestId)

	effect, err := s.eng.Check(r.Context(), req)
	if err != nil {
		if errors.Is(err, engine.ErrNoPoliciesMatched) {
			writeResponse(log, w, req.RequestId, http.StatusUnauthorized, "No policies matched", sharedv1.Effect_EFFECT_DENY)
			return
		}

		log.Errorw("Policy check failed", "error", err)
		writeResponse(log, w, req.RequestId, http.StatusInternalServerError, "Internal server error", sharedv1.Effect_EFFECT_DENY)
		return
	}

	log.Infow("Decision", "effect", sharedv1.Effect_name[int32(effect)])

	switch effect {
	case sharedv1.Effect_EFFECT_ALLOW:
		writeResponse(log, w, req.RequestId, http.StatusOK, "Allow", effect)
	default:
		writeResponse(log, w, req.RequestId, http.StatusUnauthorized, "Deny", effect)
	}
}

func writeResponse(log *zap.SugaredLogger, w http.ResponseWriter, requestID string, code int, msg string, effect sharedv1.Effect) {
	respBytes, err := protojson.Marshal(&responsev1.Response{
		RequestId:     requestID,
		StatusCode:    uint32(code),
		StatusMessage: msg,
		Effect:        effect,
	})
	if err != nil {
		log.Errorw("Failed to marshal response", "error", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)

		return
	}

	w.Header().Add("Content-type", "application/json")
	w.WriteHeader(code)
	if _, err := w.Write(respBytes); err != nil {
		log.Errorw("Failed to write response", "error", err)
	}
}

func (s *Server) handleAdminPolicy(w http.ResponseWriter, r *http.Request) {
	defer cleanup(r)

	log := s.log.Named("admin.policy")

	rws, ok := s.store.(storage.WritableStore)
	if !ok {
		log.Warnw("Store is read-only: rejecting policy admin request")
		http.Error(w, "Not supported", http.StatusNotImplemented)

		return
	}

	var fn func(context.Context, *policyv1.Policy) error
	var action string

	switch r.Method {
	case http.MethodPut, http.MethodPost:
		fn = rws.AddOrUpdate
		action = "AddOrUpdate"
	case http.MethodDelete:
		fn = rws.Remove
		action = "Remove"
	default:
		http.Error(w, "Unsupported method", http.StatusMethodNotAllowed)
		return
	}

	p, err := policy.ReadPolicy(&io.LimitedReader{R: r.Body, N: maxRequestSize})
	if err != nil {
		log.Errorw("Failed to read request body", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)

		return
	}

	modName := namer.ModuleName(p)

	if err := fn(r.Context(), p); err != nil {
		log.Errorw("Failed to perform action on policy", "policy", modName, "action", action, "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)

		return
	}

	log.Infow("Policy action successful", "policy", modName, "action", action)
	fmt.Fprintf(w, "OK\n")
}
