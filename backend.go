// SPDX-License-Identifier: MPL-2.0
// Copyright (c) HashiCorp, Inc.
// Copyright (c) Matter Labs

package vault_auth_tee

import (
	"context"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const operationPrefixTee = "tee"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

func Backend() *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login",
			},
		},
		Paths: []*framework.Path{
			pathInfo(&b),
			pathLogin(&b),
			pathListTees(&b),
			pathTees(&b),
		},
		AuthRenew:      b.loginPathWrapper(b.pathLoginRenew),
		BackendType:    logical.TypeCredential,
		RunningVersion: "v" + Version,
	}

	return &b
}

type backend struct {
	*framework.Backend
}

const backendHelp = `
The "tee" credential provider allows authentication using
remote attestation verification together with TLS client certificates.
A client connects to Vault and uses the "login" endpoint to generate a client token.

Trusted execution environments are configured using the "tees/" endpoint
by a user with root access. Authentication is then done
by supplying the attestation report, the attestation collateral
and the client certificate for "login".
`
