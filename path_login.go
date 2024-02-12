// SPDX-License-Identifier: MPL-2.0
// Copyright (c) HashiCorp, Inc.
// Copyright (c) Matter Labs

package vault_auth_tee

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/cidrutil"
	"github.com/hashicorp/vault/sdk/helper/policyutil"
	"github.com/hashicorp/vault/sdk/logical"
)

var timeNowFunc = func() (time.Time, error) {
	return getRoughNtsUnixTime()
}

func pathLogin(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "login",
		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTee,
			OperationVerb:   "login",
		},
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the tee role to authenticate against.",
			},
			"type": {
				Type:        framework.TypeString,
				Description: "The type of the TEE.",
			},
			"quote": {
				Type:        framework.TypeString,
				Description: "The quote Base64 encoded.",
			},
			"collateral": {
				Type:        framework.TypeString,
				Description: "The collateral Json encoded.",
			},
			"challenge": {
				Type:        framework.TypeString,
				Description: "Hex encoded bytes to include in the attestation report of the vault quote",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation:         b.loginPathWrapper(b.pathLogin),
			logical.AliasLookaheadOperation: b.pathLoginAliasLookahead,
			logical.ResolveRoleOperation:    b.loginPathWrapper(b.pathLoginResolveRole),
		},
	}
}

func (b *backend) loginPathWrapper(wrappedOp func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error)) framework.OperationFunc {
	return func(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
		return wrappedOp(ctx, req, data)
	}
}

func (b *backend) pathLoginResolveRole(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	quoteBase64 := data.Get("quote").(string)
	if quoteBase64 == "" {
		return nil, fmt.Errorf("missing quote")
	}

	quoteBytes, err := base64.StdEncoding.DecodeString(quoteBase64)
	if err != nil {
		return logical.ErrorResponse("quote decode error"), nil
	}

	var quote = Quote{}
	var byteReader = bytes.NewReader(quoteBytes)
	err = binary.Read(byteReader, binary.BigEndian, &quote)
	if err != nil {
		return logical.ErrorResponse("quote decode error"), nil
	}

	names, err := req.Storage.List(ctx, "tee/")
	if err != nil {
		return logical.ErrorResponse("no TEE was matched by this request"), nil
	}

	rb := quote.ReportBody

	mrSignerHex := hex.EncodeToString(rb.MrSigner[:])
	mrEnclaveHex := hex.EncodeToString(rb.MrEnclave[:])

	for _, name := range names {
		entry, err := b.Tee(ctx, req.Storage, strings.TrimPrefix(name, "tee/"))
		if err != nil {
			b.Logger().Error("failed to load trusted tee", "name", name, "error", err)
			continue
		}
		if entry == nil {
			// This could happen when the name was provided and the tee doesn't exist,
			// or just if between the LIST and the GET the tee was deleted.
			continue
		}

		if entry.SgxMrsigner != "" && entry.SgxMrsigner != mrSignerHex {
			continue
		}
		if entry.SgxMrenclave != "" && entry.SgxMrenclave != mrEnclaveHex {
			continue
		}
		if entry.SgxIsvProdid != int(binary.LittleEndian.Uint16(rb.IsvProdid[:])) {
			continue
		}
		return logical.ResolveRoleResponse(name)
	}
	return logical.ErrorResponse("no TEE was matched by this request"), nil
}

func (b *backend) pathLoginAliasLookahead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	return &logical.Response{
		Auth: &logical.Auth{
			Alias: &logical.Alias{
				Name: name,
			},
		},
	}, nil

}

func hashPublicKey256(pub interface{}) ([]byte, error) {
	pubBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}
	result := sha256.Sum256(pubBytes)
	return result[:], nil
}

func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {
		if v == e {
			return true
		}
	}
	return false
}

func (b *backend) pathLogin(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return nil, fmt.Errorf("missing name")
	}

	// Allow constraining the login request to a single TeeEntry
	entry, err := b.Tee(ctx, req.Storage, strings.TrimPrefix(name, "tee/"))

	if err != nil {
		return logical.ErrorResponse(fmt.Sprintf("no TEE matching for this login name; additionally got errors during verification: %v", err)), nil
	}

	if entry == nil {
		return logical.ErrorResponse(fmt.Sprintf("no TEE matching for this login name")), nil
	}

	// Get the connection state
	if req.Connection == nil || req.Connection.ConnState == nil {
		return logical.ErrorResponse("tls connection required"), nil
	}
	connState := req.Connection.ConnState

	if connState.PeerCertificates == nil || len(connState.PeerCertificates) == 0 {
		return logical.ErrorResponse("client certificate must be supplied"), nil
	}

	clientCert := connState.PeerCertificates[0]

	// verify self-signed certificate
	roots := x509.NewCertPool()
	roots.AddCert(clientCert)
	_, err = clientCert.Verify(x509.VerifyOptions{Roots: roots})
	if err != nil {
		return logical.ErrorResponse("client certificate must be self-signed"), nil
	}

	if len(entry.TokenBoundCIDRs) > 0 {
		if req.Connection == nil {
			b.Logger().Warn("token bound CIDRs found but no connection information available for validation")
			return nil, logical.ErrPermissionDenied
		}
		if !cidrutil.RemoteAddrIsOk(req.Connection.RemoteAddr, entry.TokenBoundCIDRs) {
			return nil, logical.ErrPermissionDenied
		}
	}

	if clientCert.PublicKey == nil {
		return logical.ErrorResponse("no public key found in client certificate"), nil
	}

	hashClientPk, err := hashPublicKey256(clientCert.PublicKey)

	if err != nil {
		return logical.ErrorResponse("error hashing public key"), nil
	}

	teeType := data.Get("type").(string)

	if _, ok := entry.Types[teeType]; !ok {
		return logical.ErrorResponse(fmt.Sprintf("type `%s` not supported for `%s`", teeType, name)), nil
	}

	quote := data.Get("quote").(string)
	quoteBytes, err := base64.StdEncoding.DecodeString(quote)
	if err != nil {
		return logical.ErrorResponse("quote decode error"), nil
	}

	// Do a quick check of the quote before doing the expensive verification
	var quoteStart = Quote{}
	var byteReader = bytes.NewReader(quoteBytes)
	err = binary.Read(byteReader, binary.BigEndian, &quoteStart)
	if err != nil {
		return logical.ErrorResponse("quote decode error"), nil
	}
	reportBody := quoteStart.ReportBody

	if !bytes.Equal(reportBody.ReportData[:32], hashClientPk) {
		return logical.ErrorResponse("client certificate's hashed public key not in report data of attestation quote report"), nil
	}

	mrSignerHex := hex.EncodeToString(reportBody.MrSigner[:])
	mrEnclaveHex := hex.EncodeToString(reportBody.MrEnclave[:])

	if entry.SgxMrsigner != "" && entry.SgxMrsigner != mrSignerHex {
		return logical.ErrorResponse("`sgx_mrsigner` does not match"), nil
	}
	if entry.SgxMrenclave != "" && entry.SgxMrenclave != mrEnclaveHex {
		return logical.ErrorResponse("`sgx_mrenclave` does not match"), nil
	}
	if entry.SgxIsvProdid != int(binary.LittleEndian.Uint16(reportBody.IsvProdid[:])) {
		return logical.ErrorResponse("`sgx_isv_prodid` does not match"), nil
	}
	if entry.SgxMinIsvSvn > int(binary.LittleEndian.Uint16(reportBody.IsvSvn[:])) {
		return logical.ErrorResponse("`sgx_isv_svn` too low"), nil
	}

	// Decode the collateral
	jsonCollateralBlob := data.Get("collateral").(string)
	var collateral TeeQvCollateral
	err = json.Unmarshal([]byte(jsonCollateralBlob), &collateral)
	if err != nil {
		return logical.ErrorResponse("collateral unmarshal error"), nil
	}

	now, err := timeNowFunc()
	if err != nil {
		return logical.ErrorResponse("time error"), nil
	}

	// Do the actual remote attestation verification
	result, err := SgxVerifyRemoteReportCollateral(quoteBytes, collateral, now.Unix())
	if err != nil {
		return logical.ErrorResponse("sgx verify error"), nil
	}

	if result.CollateralExpired {
		return logical.ErrorResponse("collateral expired"), nil
	}

	if result.VerificationResult != SgxQlQvResultOk {
		if entry.SgxAllowedTcbLevels[result.VerificationResult] != true {
			return logical.ErrorResponse("invalid TCB state %v", result.VerificationResult), nil
		}
	}

	skid := base64.StdEncoding.EncodeToString(clientCert.SubjectKeyId)
	akid := base64.StdEncoding.EncodeToString(clientCert.AuthorityKeyId)
	pkid := base64.StdEncoding.EncodeToString(hashClientPk)

	expirationDate := time.Unix(result.EarliestExpirationDate, 0)
	metadata := map[string]string{
		"tee_name":                   entry.Name,
		"collateral_expiration_date": expirationDate.Format(time.RFC3339),
	}

	auth := &logical.Auth{
		InternalData: map[string]interface{}{
			"subject_key_id":   skid,
			"authority_key_id": akid,
			"hash_public_key":  pkid,
		},
		Alias: &logical.Alias{
			Name: entry.Name,
		},
		DisplayName: entry.DisplayName,
		Metadata:    metadata,
	}

	entry.PopulateTokenAuth(auth)

	if !now.Add(auth.TTL).After(expirationDate) {
		auth.TTL = expirationDate.Sub(now)
	}

	if !now.Add(auth.MaxTTL).After(expirationDate) {
		auth.MaxTTL = expirationDate.Sub(now)
	}

	respData := make(map[string]interface{})

	challenge := data.Get("challenge").(string)
	if challenge != "" {
		challengeBytes, err := hex.DecodeString(challenge)
		if err != nil {
			return logical.ErrorResponse("challenge decode error"), nil
		}

		ourQuote, err := SgxGetQuote(challengeBytes)
		if err != nil {
			return logical.ErrorResponse("vault quote error"), nil
		}

		quoteBase64 := base64.StdEncoding.EncodeToString(ourQuote)

		respData["quote"] = quoteBase64

		collateral, err := SgxGetCollateral(ourQuote)
		if err != nil {
			return logical.ErrorResponse("vault collateral error"), nil
		}

		collateralJson, err := json.Marshal(collateral)
		if err != nil {
			return logical.ErrorResponse("vault collateral json error"), nil
		}

		respData["collateral"] = string(collateralJson)
	}

	return &logical.Response{
		Auth: auth,
		Data: respData,
	}, nil
}

func (b *backend) pathLoginRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	clientCerts := req.Connection.ConnState.PeerCertificates
	if len(clientCerts) == 0 {
		return logical.ErrorResponse("no client certificate found"), nil
	}
	hashClientPk, err := hashPublicKey256(clientCerts[0].PublicKey)
	if err != nil {
		return logical.ErrorResponse("error hashing public key"), nil
	}
	skid := base64.StdEncoding.EncodeToString(clientCerts[0].SubjectKeyId)
	akid := base64.StdEncoding.EncodeToString(clientCerts[0].AuthorityKeyId)
	pkid := base64.StdEncoding.EncodeToString(hashClientPk)

	// Certificate should not only match a registered tee policy.
	// Also, the identity of the certificate presented should match the identity of the certificate used during login
	if req.Auth.InternalData["subject_key_id"] != skid && req.Auth.InternalData["authority_key_id"] != akid && req.Auth.InternalData["hash_public_key"] != pkid {
		return nil, fmt.Errorf("client identity during renewal not matching client identity used during login")
	}

	// Get the tee and use its TTL
	tee, err := b.Tee(ctx, req.Storage, req.Auth.Metadata["tee_name"])
	if err != nil {
		return nil, err
	}
	if tee == nil {
		// User no longer exists, do not renew
		return nil, nil
	}

	if !policyutil.EquivalentPolicies(tee.TokenPolicies, req.Auth.TokenPolicies) {
		return nil, fmt.Errorf("policies have changed, not renewing")
	}

	expirationDate, err := time.Parse(time.RFC3339, req.Auth.Metadata["collateral_expiration_date"])
	if err != nil {
		return logical.ErrorResponse("error parsing `collateral_expiration_date` metadata"), nil
	}

	now, err := timeNowFunc()
	if err != nil {
		return logical.ErrorResponse("time error"), nil
	}

	if expirationDate.Before(now) {
		return logical.ErrorResponse("Collateral expired"), nil
	}

	resp := &logical.Response{Auth: req.Auth}

	fmt.Errorf("XXXXXXXX: tee.TokenTTL: %v\n", tee.TokenTTL)

	if now.Add(tee.TokenTTL).After(expirationDate) {
		resp.Auth.TTL = tee.TokenTTL
	} else {
		resp.Auth.TTL = expirationDate.Sub(now)
	}

	if now.Add(tee.TokenMaxTTL).After(expirationDate) {
		resp.Auth.MaxTTL = tee.TokenMaxTTL
	} else {
		resp.Auth.MaxTTL = expirationDate.Sub(now)
	}

	resp.Auth.Period = tee.TokenPeriod
	return resp, nil
}
