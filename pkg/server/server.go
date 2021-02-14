package server

import (
	"context"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/gorilla/mux"
	"go.uber.org/zap"
	"google.golang.org/protobuf/encoding/protojson"

	requestv1 "github.com/charithe/menshen/pkg/generated/request/v1"
	responsev1 "github.com/charithe/menshen/pkg/generated/response/v1"
	sharedv1 "github.com/charithe/menshen/pkg/generated/shared/v1"
	"github.com/charithe/menshen/pkg/policy"
)

const maxRequestSize = 1024 * 1024 // 1 MiB

type Server struct {
	checker *policy.Checker
}

func New(checker *policy.Checker) *Server {
	return &Server{checker: checker}
}

func (s *Server) Handler() http.Handler {
	r := mux.NewRouter()
	r.HandleFunc("/v1/check", s.handleCheck)

	return r
}

func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	defer func() {
		if r.Body != nil {
			_, _ = io.Copy(ioutil.Discard, r.Body)
			r.Body.Close()
		}
	}()

	log := zap.S().Named("http.check")

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

	log = log.With("request_id", req.RequestId)

	effect, err := s.checker.Check(context.TODO(), req)
	if err != nil {
		log.Errorw("Failed to check policies", "error", err)
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
