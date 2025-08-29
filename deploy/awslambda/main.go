// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"go.uber.org/multierr"
)

const cerbosHTTPAddr = "unix:/tmp/cerbos.http.sock"

func main() {
	gw, err := NewGateway(cerbosHTTPAddr)
	if err != nil {
		log.Print("failed to create a gateway")
		return
	}
	lambda.StartHandler(gw)
}

var ErrNotStarted = errors.New("timeout exceeded starting Cerbos")

type Gateway struct {
	httpClient    *http.Client
	cerbosAddress *url.URL
	socketPath    string
}

// NewGateway creates a new Gateway instance.
func NewGateway(addr string) (*Gateway, error) {
	if addr == "" {
		return nil, errors.New("cerbos address not provided")
	}

	var socketPath string
	var u *url.URL
	var err error

	if after, ok := strings.CutPrefix(addr, "unix:"); ok {
		socketPath = after
		u = &url.URL{Scheme: "http", Host: "localhost"}
	} else {
		u, err = url.Parse(addr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse cerbos address: %w", err)
		}
	}

	client := &http.Client{}
	if socketPath != "" {
		transport := &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return net.Dial("unix", socketPath)
			},
		}
		client.Transport = transport
	}

	gw := &Gateway{
		cerbosAddress: u,
		socketPath:    socketPath,
		httpClient:    client,
	}

	return gw, nil
}

func (g *Gateway) Invoke(ctx context.Context, payload []byte) ([]byte, error) {
	var evt events.APIGatewayV2HTTPRequest
	if err := json.Unmarshal(payload, &evt); err != nil {
		return []byte{}, err
	}

	r, err := g.newRequest(ctx, evt)
	if err != nil {
		return nil, err
	}

	resp, err := g.httpClient.Do(r)
	if err != nil {
		err := fmt.Errorf("error calling HTTP endpoint %q: %w", r.URL.String(), err)
		log.Print(err)
		return nil, err
	}

	res, err := MkGatewayResponse(resp)
	if err != nil {
		log.Print(err)
		res = &events.APIGatewayV2HTTPResponse{
			StatusCode: http.StatusInternalServerError,
			Body:       err.Error(),
			Headers:    map[string]string{"content-type": "text/plain; charset=utf-8"},
		}
	}
	return json.Marshal(res)
}

// newRequest returns a new http.Request from the given Lambda event.
func (g *Gateway) newRequest(ctx context.Context, e events.APIGatewayV2HTTPRequest) (*http.Request, error) {
	// path
	u, err := url.Parse(e.RawPath)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RawPath %q: %w", e.RawPath, err)
	}

	u.RawQuery = e.RawQueryString

	u.Scheme = g.cerbosAddress.Scheme
	u.Host = g.cerbosAddress.Host

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

	// remote addr
	req.RemoteAddr = e.RequestContext.HTTP.SourceIP

	// header fields
	for k, values := range e.Headers {
		for v := range strings.SplitSeq(values, ",") {
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
	req.Host = req.URL.Host

	return req, nil
}

func MkGatewayResponse(hresp *http.Response) (res *events.APIGatewayV2HTTPResponse, err error) {
	res = new(events.APIGatewayV2HTTPResponse)
	res.Headers = make(map[string]string)

	defer multierr.AppendInvoke(&err, multierr.Close(hresp.Body))
	body, err := io.ReadAll(hresp.Body)
	res.IsBase64Encoded, err = isBinary(hresp.Header)
	if err != nil {
		return nil, err
	}
	if res.IsBase64Encoded {
		res.Body = base64.StdEncoding.EncodeToString(body)
	} else {
		res.Body = string(body)
	}
	// copy headers
	for k, vv := range hresp.Header {
		res.Headers[strings.ToLower(k)] = strings.Join(vv, ",")
	}
	// see https://aws.amazon.com/blogs/compute/simply-serverless-using-aws-lambda-to-expose-custom-cookies-with-api-gateway/
	res.Cookies = hresp.Header["Set-Cookie"]
	res.StatusCode = hresp.StatusCode
	return res, nil
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
