// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package lambda

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-lambda-go/events"
	"go.uber.org/zap"
)

// PanicListener panics if used.
type PanicListener struct {
	net.Listener
}

type Gateway struct {
	Handler http.Handler
	Log     *zap.Logger
}

func (g *Gateway) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	var evt events.APIGatewayV2HTTPRequest
	g.Log.Info("Gateway handler invoked")
	if err := json.Unmarshal(payload, &evt); err != nil {
		return []byte{}, err
	}

	r, err := NewRequest(ctx, evt)
	if err != nil {
		return []byte{}, err
	}

	w := NewResponseWriter()
	g.Log.Info("Calling HTTP handler")
	g.Handler.ServeHTTP(w, r)

	resp, err := w.End()
	g.Log.Debug("Received a response", zap.String("resp.body", resp.Body), zap.Int("resp.statusCode", resp.StatusCode))

	if err != nil {
		resp = &events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
			Headers:    map[string]string{"content-type": "text/plain; charset=utf-8"},
		}
	}
	return json.Marshal(resp)
}

// NewRequest returns a new http.Request from the given Lambda event.
func NewRequest(ctx context.Context, e events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	// path
	u, err := url.Parse(e.RawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RawPath %q: %w", e.RawPath, err)
	}

	u.RawQuery = e.RawQueryString

	// base64 encoded body
	body := e.Body
	if e.IsBase64Encoded {
		b, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			return nil, fmt.Errorf("failed to base64 decode body: %w", err)
		}
		body = string(b)
	}

	req, err := http.NewRequestWithContext(ctx, e.RequestContext.HTTP.Method, u.String(), strings.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	// manually set RequestURI because NewRequest is for clients and req.RequestURI is for servers
	req.RequestURI = u.RequestURI()

	// remote addr
	req.RemoteAddr = e.RequestContext.HTTP.SourceIP

	// header fields
	for k, values := range e.Headers {
		for _, v := range strings.Split(values, ",") {
			req.Header.Add(k, v)
		}
	}
	for _, c := range e.Cookies {
		req.Header.Add("Cookie", c)
	}

	// content-length
	if req.Header.Get("Content-Length") == "" && body != "" {
		req.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	// custom fields
	req.Header.Set("X-Request-Id", e.RequestContext.RequestID)
	req.Header.Set("X-Stage", e.RequestContext.Stage)

	// xray support
	if traceID := ctx.Value("x-amzn-trace-id"); traceID != nil {
		req.Header.Set("X-Amzn-Trace-Id", fmt.Sprintf("%v", traceID))
	}

	// host
	req.URL.Host = req.Header.Get("Host")
	req.Host = req.URL.Host

	return req, nil
}

// ResponseWriter implements the http.ResponseWriter interface
// in order to support the API Gateway Lambda HTTP "protocol".
type ResponseWriter struct {
	out           events.APIGatewayV2HTTPResponse
	buf           bytes.Buffer
	header        http.Header
	headerWritten bool
	trailers      []string // trailer headers
	mu            sync.Mutex
}

// NewResponseWriter returns a new response writer to capture http output.
func NewResponseWriter() *ResponseWriter {
	return &ResponseWriter{
		header: make(http.Header),
	}
}

func (w *ResponseWriter) Header() http.Header {
	return w.header
}

// Write implementation.
func (w *ResponseWriter) Write(b []byte) (int, error) {
	if !w.headerWritten { // not sync access here, since writeHeader does it again
		w.WriteHeader(http.StatusOK)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	return w.buf.Write(b)
}

func (w *ResponseWriter) addHeaderValue(h string, vv []string) {
	w.out.Headers[strings.ToLower(h)] = strings.Join(vv, ",")
}

// WriteHeader implementation.
func (w *ResponseWriter) WriteHeader(status int) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.headerWritten {
		return
	}

	if w.Header().Get("Content-Type") == "" {
		t := http.DetectContentType(w.buf.Bytes())
		w.Header().Set("Content-Type", t)
	}

	w.out.StatusCode = status

	w.out.Headers = make(map[string]string, len(w.Header()))

	for k, v := range w.Header() {
		if k == "Trailer" {
			w.trailers = append(w.trailers, v...)
		} else if !strings.HasPrefix(k, http.TrailerPrefix) { // a regular header
			w.addHeaderValue(k, v)
		}
	}

	w.headerWritten = true
}

// End the request.
func (w *ResponseWriter) End() (*events.APIGatewayV2HTTPResponse, error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	var err error
	w.out.IsBase64Encoded, err = isBinary(w.header)
	if err != nil {
		return nil, err
	}
	if w.out.IsBase64Encoded {
		w.out.Body = base64.StdEncoding.EncodeToString(w.buf.Bytes())
	} else {
		w.out.Body = w.buf.String()
	}

	if len(w.trailers) > 0 {
		h := w.Header()
		for _, k := range w.trailers {
			if v, ok := h[http.CanonicalHeaderKey(k)]; ok {
				w.addHeaderValue(k, v)
			}
		}
		for k, v := range h {
			if strings.HasPrefix(k, http.TrailerPrefix) { // a regular header
				w.addHeaderValue(strings.TrimPrefix(k, http.TrailerPrefix), v)
			}
		}
	}
	// see https://aws.amazon.com/blogs/compute/simply-serverless-using-aws-lambda-to-expose-custom-cookies-with-api-gateway/
	w.out.Cookies = w.header["Set-Cookie"]
	w.header.Del("Set-Cookie")

	return &w.out, nil
}

// isBinary checks content type of the returns true if it describes binary data
// It uses a non-exhaustive list of binary content types.
func isBinary(h http.Header) (bool, error) {
	kind := h.Get("Content-Type")
	t, _, err := mime.ParseMediaType(kind)
	if err != nil {
		return false, fmt.Errorf("failed to parse media type %q: %w", kind, err)
	}
	return strings.HasPrefix(t, "image") ||
		strings.HasPrefix(t, "gzip") ||
		t == "application/octet-stream", nil
}
