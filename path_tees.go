// SPDX-License-Identifier: MPL-2.0
// Copyright (c) HashiCorp, Inc.
// Copyright (c) Matter Labs

package vault_auth_tee

import "C"
import (
	"context"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/tokenutil"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathListTees(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "tees/?",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTee,
			OperationSuffix: "tees",
			Navigation:      true,
			ItemType:        "Tee",
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathTeeList,
		},

		HelpSynopsis:    pathTeeHelpSyn,
		HelpDescription: pathTeeHelpDesc,
	}
}

func pathTees(b *backend) *framework.Path {
	p := &framework.Path{
		Pattern: "tees/" + framework.GenericNameRegex("name"),

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixTee,
			OperationSuffix: "tee",
			Action:          "Create",
			ItemType:        "Tee",
		},

		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "The name of the Tee, which passes remote attestation verification",
			},

			"types": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The types of the TEE.",
			},

			"sgx_mrsigner": {
				Type:        framework.TypeString,
				Description: `The SGX mrsigner hex value to check the attestation report against`,
			},

			"sgx_mrenclave": {
				Type:        framework.TypeString,
				Description: `The SGX mrenclave hex value to check the attestation report against`,
			},

			"sgx_isv_prodid": {
				Type:        framework.TypeInt,
				Description: `The SGX isv_prodid value to check the attestation report against`,
			},

			"sgx_min_isv_svn": {
				Type:        framework.TypeInt,
				Description: `The SGX minimum isv_svn value to check the attestation report against`,
			},

			"sgx_allowed_tcb_levels": {
				Type: framework.TypeCommaStringSlice,
				Description: `A comma seperated list of allowed SGX TCB states.
Allowed values are: ConfigNeeded, OutOfDate, OutOfDateConfigNeeded, SwHardeningNeeded, ConfigAndSwHardeningNeeded`,
			},

			"display_name": {
				Type:        framework.TypeString,
				Description: `The display name to use for clients using this certificate.`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.DeleteOperation: b.pathTeeDelete,
			logical.ReadOperation:   b.pathTeeRead,
			logical.UpdateOperation: b.pathTeeWrite,
		},

		HelpSynopsis:    pathTeeHelpSyn,
		HelpDescription: pathTeeHelpDesc,
	}

	tokenutil.AddTokenFields(p.Fields)
	return p
}

func (b *backend) Tee(ctx context.Context, s logical.Storage, n string) (*TeeEntry, error) {
	entry, err := s.Get(ctx, "tee/"+strings.ToLower(n))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result TeeEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathTeeDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	err := req.Storage.Delete(ctx, "tee/"+strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathTeeList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tees, err := req.Storage.List(ctx, "tee/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(tees), nil
}

func (b *backend) pathTeeRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	tee, err := b.Tee(ctx, req.Storage, strings.ToLower(d.Get("name").(string)))
	if err != nil {
		return nil, err
	}
	if tee == nil {
		return nil, nil
	}

	data := map[string]interface{}{
		"display_name":           tee.DisplayName,
		"types":                  tee.Types,
		"sgx_mrsigner":           tee.SgxMrsigner,
		"sgx_mrenclave":          tee.SgxMrenclave,
		"sgx_isv_prodid":         tee.SgxIsvProdid,
		"sgx_min_isv_svn":        tee.SgxMinIsvSvn,
		"sgx_allowed_tcb_levels": tee.SgxAllowedTcbLevels,
	}
	tee.PopulateTokenData(data)

	return &logical.Response{
		Data: data,
	}, nil
}

func (b *backend) pathTeeWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(d.Get("name").(string))

	tee, err := b.Tee(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	if tee == nil {
		tee = &TeeEntry{
			Name: name,
		}
	}

	// Get non tokenutil fields
	if displayNameRaw, ok := d.GetOk("display_name"); ok {
		tee.DisplayName = displayNameRaw.(string)
	}

	if teeTypes, ok := d.GetOk("types"); ok {
		tee.Types = make(map[string]bool)
		handled := make(map[string]bool)
		for _, t := range teeTypes.([]string) {
			// only SGX supported for now
			if _, ok = handled[t]; ok {
				return logical.ErrorResponse(fmt.Sprintf("duplicate TEE type `%s`", t)), nil
			}
			if t == "sgx" {
				tee.Types[t] = true
				handled[t] = true
				response, err := handleSGXConfig(d, tee)
				if response != nil || err != nil {
					return response, err
				}
			} else {
				return logical.ErrorResponse(fmt.Sprintf("invalid TEE type `%s`", t)), nil
			}
		}
	} else {
		return logical.ErrorResponse("missing TEE types"), nil
	}

	// Get tokenutil fields
	if err := tee.ParseTokenFields(req, d); err != nil {
		return logical.ErrorResponse(err.Error()), logical.ErrInvalidRequest
	}

	var resp logical.Response

	systemDefaultTTL := b.System().DefaultLeaseTTL()
	if tee.TokenTTL > systemDefaultTTL {
		resp.AddWarning(fmt.Sprintf("Given ttl of %d seconds is greater than current mount/system default of %d seconds", tee.TokenTTL/time.Second, systemDefaultTTL/time.Second))
	}
	systemMaxTTL := b.System().MaxLeaseTTL()
	if tee.TokenMaxTTL > systemMaxTTL {
		resp.AddWarning(fmt.Sprintf("Given max_ttl of %d seconds is greater than current mount/system default of %d seconds", tee.TokenMaxTTL/time.Second, systemMaxTTL/time.Second))
	}
	if tee.TokenMaxTTL != 0 && tee.TokenTTL > tee.TokenMaxTTL {
		return logical.ErrorResponse("ttl should be shorter than max_ttl"), nil
	}
	if tee.TokenPeriod > systemMaxTTL {
		resp.AddWarning(fmt.Sprintf("Given period of %d seconds is greater than the backend's maximum TTL of %d seconds", tee.TokenPeriod/time.Second, systemMaxTTL/time.Second))
	}

	// Default the display name to the certificate name if not given
	if tee.DisplayName == "" {
		tee.DisplayName = name
	}

	// Store it
	entry, err := logical.StorageEntryJSON("tee/"+name, tee)
	if err != nil {
		return nil, err
	}
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	if len(resp.Warnings) == 0 {
		return nil, nil
	}

	return &resp, nil
}

func handleSGXConfig(d *framework.FieldData, tee *TeeEntry) (*logical.Response, error) {
	if sgxMrsignerRaw, ok := d.GetOk("sgx_mrsigner"); ok {
		tee.SgxMrsigner = strings.ToLower(sgxMrsignerRaw.(string))
		if tee.SgxMrsigner != "" {
			b, err := hex.DecodeString(tee.SgxMrsigner)
			if err != nil || len(b) != 32 {
				return logical.ErrorResponse("`sgx_mrsigner` must be 32 byte hex encoded"), nil
			}
		}
	}

	if sgxMrenclaveRaw, ok := d.GetOk("sgx_mrenclave"); ok {
		tee.SgxMrenclave = strings.ToLower(sgxMrenclaveRaw.(string))
		if tee.SgxMrenclave != "" {
			b, err := hex.DecodeString(tee.SgxMrenclave)
			if err != nil || len(b) != 32 {
				return logical.ErrorResponse("`sgx_mrenclave` must be 32 byte hex encoded"), nil
			}
		}
	}

	if tee.SgxMrsigner == "" && tee.SgxMrenclave == "" {
		return logical.ErrorResponse("either `sgx_mrsigner` or `sgx_mrenclave` must be set"), nil
	}

	if sgxIsvProdidRaw, ok := d.GetOk("sgx_isv_prodid"); ok {
		tee.SgxIsvProdid = sgxIsvProdidRaw.(int)
	}

	if sgxMinIsvSvnRaw, ok := d.GetOk("sgx_min_isv_svn"); ok {
		tee.SgxMinIsvSvn = sgxMinIsvSvnRaw.(int)
	}

	if sgxAllowedTcbLevelsRaw, ok := d.GetOk("sgx_allowed_tcb_levels"); ok {
		tee.SgxAllowedTcbLevels = make(map[SgxQlQvResult]bool)
		for _, v := range sgxAllowedTcbLevelsRaw.([]string) {
			var state SgxQlQvResult
			switch v {
			case "Ok":
				state = SgxQlQvResultOk
			case "ConfigNeeded":
				state = SgxQlQvResultConfigNeeded
			case "OutOfDate":
				state = SgxQlQvResultOutOfDate
			case "OutOfDateConfigNeeded":
				state = SgxQlQvResultOutOfDateConfigNeeded
			case "SwHardeningNeeded":
				state = SgxQlQvResultSwHardeningNeeded
			case "ConfigAndSwHardeningNeeded":
				state = SgxQlQvResultConfigAndSwHardeningNeeded
			default:
				return logical.ErrorResponse("invalid sgx_allowed_tcb_levels value"), logical.ErrInvalidRequest
			}
			tee.SgxAllowedTcbLevels[state] = true
		}
	}
	return nil, nil
}

type TeeEntry struct {
	tokenutil.TokenParams

	Name                string
	DisplayName         string
	Types               map[string]bool
	SgxMrsigner         string
	SgxMrenclave        string
	SgxIsvProdid        int
	SgxMinIsvSvn        int
	SgxAllowedTcbLevels map[SgxQlQvResult]bool
}

const pathTeeHelpSyn = `
Manage TEE remote attestation parameters used for authentication.`

const pathTeeHelpDesc = `
This endpoint allows you to create, read, update, and delete TEEs
that are allowed to authenticate.

Deleting a TEE will not revoke auth for prior authenticated connections.
To do this, do a revoke on "login". If you don't need to revoke login immediately,
then the next renew will cause the lease to expire.
`
