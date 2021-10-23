package main

import (
	"context"
	"github.com/cerbos/cerbos/internal/server"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
)

var srv *server.Server

func handler(request events.APIGatewayProxyRequest) (events.APIGatewayProxyResponse, error) {
	ctx := context.Background()
	if srv != nil {
		conf := &server.Conf{}
		srv = server.NewServer(conf)
		go srv.Start(ctx, server.Param{})
		srv.WaitInit()
	}
	// submit request
}

func main() {
	lambda.Start(handler)
}
