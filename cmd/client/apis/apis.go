// Copyright 2021 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package apis

import (
	"context"
	"fmt"
	"net/http"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/jsonpb"

	apigee "github.com/srinandan/external-callout/pkg/apigee"
	common "github.com/srinandan/sample-apps/common"
)

//endpoint to reach the ext callout service
var extCalloutServiceEndpoint = os.Getenv("EXT_CALLOUT_SVC")

func initClient(r *http.Request) (extClient apigee.ExternalCalloutServiceClient, conn *grpc.ClientConn, err error) {

	if extCalloutServiceEndpoint == "" {
		extCalloutServiceEndpoint = "localhost:50051"
	}

	conn, err = grpc.Dial(extCalloutServiceEndpoint, grpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("did not connect: %v", err)
	}

	extClient = apigee.NewExternalCalloutServiceClient(conn)

	return extClient, conn, nil
}

func closeClient(conn *grpc.ClientConn) {
	if conn != nil {
		defer conn.Close()
	}
}

func ProcessMessageHandler(w http.ResponseWriter, r *http.Request) {

	extClient, conn, err := initClient(r)
	if err != nil {
		common.ErrorHandler(w, err)
		return
	}

	defer closeClient(conn)

	ctx := context.Background()
	messageContext := apigee.MessageContext{}

	request := apigee.Request{}
	request.Content = "hello server!"

	messageContext.Request = &request

	resp, err := extClient.ProcessMessage(ctx, &messageContext)
	if err != nil {
		e, _ := status.FromError(err)
		if e.Code() == codes.Unavailable {
			common.ErrorHandler(w, err)
		} else if e.Code() == codes.PermissionDenied || e.Code() == codes.Unauthenticated {
			common.PermissionDeniedHandler(w, err)
		} else {
			common.NotFoundHandler(w, err.Error())
		}
		return
	}

	m := &jsonpb.Marshaler{}
	msgCtxResponse, err := m.MarshalToString(resp)
	if err != nil {
		common.ErrorHandler(w, err)
		return
	}

	fmt.Fprintln(w, string(msgCtxResponse))
}
