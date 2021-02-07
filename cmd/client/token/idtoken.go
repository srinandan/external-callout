// Copyright 2020 Google LLC.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package token

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/jws"

	oauthsvc "google.golang.org/api/oauth2/v2"
)

const audience = "https://www.googleapis.com/oauth2/v4/token"

// NewTokenSource creates a TokenSource that returns ID tokens with the audience
// provided and configured with the supplied options. The parameter audience may
// not be empty.
func NewTokenSource(ctx context.Context, targetAudience string, data []byte) (string, error) {
	return tokenSourceFromBytes(ctx, targetAudience, data)
}

func doExchange(token string) (payload string, err error) {
	d := url.Values{}
	d.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	d.Add("assertion", token)

	client := &http.Client{}
	req, err := http.NewRequest("POST", audience, strings.NewReader(d.Encode()))
	if err != nil {
		return payload, err
	}
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")

	resp, err := client.Do(req)
	if err != nil {
		return payload, err
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return payload, err
	}
	return string(body), nil
}

func tokenSourceFromBytes(ctx context.Context, targetAudience string, data []byte) (identityToken string, err error) {
	const algorithm = "RS256"
	const typ = "JWT"

	conf, err := google.JWTConfigFromJSON(data, oauthsvc.UserinfoEmailScope)
	if err != nil {
		return identityToken, err
	}

	header := &jws.Header{
		Algorithm: algorithm,
		Typ:       typ,
		KeyID:     conf.PrivateKeyID,
	}

	// for iap/endpoints
	private_claims := map[string]interface{}{"target_audience": "https://" + targetAudience}
	iat := time.Now()
	exp := iat.Add(time.Hour)

	payload := &jws.ClaimSet{
		Iss:           conf.Email,
		Iat:           iat.Unix(),
		Exp:           exp.Unix(),
		Aud:           audience,
		PrivateClaims: private_claims,
	}

	// from https://github.com/golang/oauth2/blob/master/internal/oauth2.go#L23
	key := conf.PrivateKey
	block, _ := pem.Decode(key)
	if block != nil {
		key = block.Bytes
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(key)
	if err != nil {
		parsedKey, err = x509.ParsePKCS1PrivateKey(key)
		if err != nil {
			return identityToken, err
		}
	}
	parsed, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		return identityToken, err
	}

	token, err := jws.Encode(header, payload, parsed)
	if err != nil {
		return identityToken, err
	}

	body, err := doExchange(token)
	if err != nil {
		return identityToken, err
	}

	return string(body), nil
}
