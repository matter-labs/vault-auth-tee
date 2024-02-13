// SPDX-License-Identifier: MPL-2.0
// Copyright (c) HashiCorp, Inc.
// Copyright (c) Matter Labs

package vault_auth_tee

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathInfo(b *backend) *framework.Path {
	return &framework.Path{
		Pattern:      "info",
		HelpSynopsis: "Display information about the plugin",
		HelpDescription: `

Displays information about the plugin, such as the plugin version and where to
get help.

`,
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathInfoRead,
		},
	}
}

// pathInfoRead corresponds to READ auth/tee/info.
func (b *backend) pathInfoRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return &logical.Response{
		Data: map[string]interface{}{
			"name":    Name,
			"version": Version,
		},
	}, nil
}
