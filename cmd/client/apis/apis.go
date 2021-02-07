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
	"crypto/tls"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	"github.com/golang/protobuf/jsonpb"

	token "github.com/srinandan/external-callout/cmd/client/token"
	apigee "github.com/srinandan/external-callout/pkg/apigee"
	common "github.com/srinandan/sample-apps/common"
)

//endpoint to reach the ext callout service
var extCalloutServiceEndpoint = os.Getenv("EXT_CALLOUT_SVC")

//obtain a google oauth token
var enableGoogleOAuth = os.Getenv("ENABLE_GOOGLE_OAUTH")

//enable TLS
var enableTLS = os.Getenv("ENABLE_TLS")

const tokenType = "Bearer"
const authorizationHeader = "Authorization"

type extCalloutOAuthCreds struct {
	AccessToken string
}

func (c *extCalloutOAuthCreds) GetRequestMetadata(context.Context, ...string) (map[string]string, error) {
	return map[string]string{
		authorizationHeader: tokenType + " " + c.AccessToken,
	}, nil
}

func (c *extCalloutOAuthCreds) RequireTransportSecurity() bool {
	return false
}

func NewTokenFromHeader(jwt string) (credentials.PerRPCCredentials, error) {
	return &extCalloutOAuthCreds{AccessToken: jwt}, nil
}

func getTransportCredentials() grpc.DialOption {
	if enableTLS == "true" {
		config := &tls.Config{
			InsecureSkipVerify: true,
		}
		return grpc.WithTransportCredentials(credentials.NewTLS(config))
	} else {
		return grpc.WithInsecure()
	}
}

func readServiceAccount() (content []byte, err error) {
	content, err = ioutil.ReadFile(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	if err != nil {
		common.Error.Println("service account was not found")
		return nil, err
	}
	return content, nil
}

func getHostname(extCalloutServiceEndpoint string) string {
	if strings.Contains(extCalloutServiceEndpoint, ":") {
		names := strings.Split(extCalloutServiceEndpoint, ":")
		return names[0]
	} else {
		return extCalloutServiceEndpoint
	}
}

func initClient(r *http.Request, ctx context.Context) (extClient apigee.ExternalCalloutServiceClient, conn *grpc.ClientConn, err error) {

	if extCalloutServiceEndpoint == "" {
		extCalloutServiceEndpoint = "localhost:50051"
	}

	if enableGoogleOAuth == "true" {
		common.Info.Println("Google OAuth is enabled")
		var creds credentials.PerRPCCredentials
		//if the google oauth token is already passed from the client, use it
		if authHeader := r.Header.Get("Authorization"); authHeader != "" {
			common.Info.Println("Using header from client")
			bearerToken := strings.Split(authHeader, " ")
			creds, _ = NewTokenFromHeader(bearerToken[1])
		} else {
			common.Info.Println("Generating ID Token")
			var content []byte
			var identityToken string
			if content, err = readServiceAccount(); err != nil {
				return nil, nil, fmt.Errorf("failed to read service account: %v", err)
			}
			if identityToken, err = token.NewTokenSource(ctx, getHostname(extCalloutServiceEndpoint), content); err != nil {
				return nil, nil, fmt.Errorf("failed to get access token: %v", err)
			}
			common.Info.Printf("ID token is %s\n", identityToken)
			creds, _ = NewTokenFromHeader(identityToken)
		}
		common.Info.Printf("Connecting to %s with credentials\n", extCalloutServiceEndpoint)
		conn, err = grpc.Dial(extCalloutServiceEndpoint, getTransportCredentials(), grpc.WithPerRPCCredentials(creds))
	} else {
		common.Info.Printf("Connecting to %s without credentials\n", extCalloutServiceEndpoint)
		conn, err = grpc.Dial(extCalloutServiceEndpoint, getTransportCredentials())
	}

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

	ctx := context.Background()

	extClient, conn, err := initClient(r, ctx)
	if err != nil {
		common.ErrorHandler(w, err)
		return
	}

	defer closeClient(conn)

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
