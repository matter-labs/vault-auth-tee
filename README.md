# vault-auth-tee
TEE remote attestation plugin for Hashicorp Vault

# ⚠️☢️☣️ WARNING: not yet for production use ☣️☢️⚠️

## Build Setup

```bash
$ wget -qO - https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key | sudo apt-key add -
$ sudo bash -c 'echo "deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main" > /etc/apt/sources.list.d/intel-sgx.list'
$ sudo apt update
$ sudo apt install -y --no-install-recommends \
    libsgx-headers \
    libsgx-enclave-common \
    libsgx-urts \
    libsgx-dcap-quote-verify \
    libsgx-dcap-quote-verify-dev
```

## Configuration

`Create` or `Update` via the `${plugin}/tees/$name` endpoint

```json
{
    "name": "TEE_role_name",
    "token_policies": "policy1,policy2,...",
    "types": "sgx",
    "sgx_mrsigner": "298037d88782e022e019b3020745b78aa40ed95c77da4bf7f3253d3a44c4fd7e",
    "sgx_mrenclave": "18946b3547d3ca036f4df7b516857e28fd512d69fed3411dc660537912faabf8",
    "sgx_isv_prodid": 0,
    "sgx_min_isv_svn": 0,
    "sgx_allowed_tcb_levels": "Ok,ConfigNeeded,OutOfDate,OutOfDateConfigNeeded,SwHardeningNeeded,ConfigAndSwHardeningNeeded"
}
```

* At least one of `sgx_mrsigner` or `sgx_mrenclave` must be set. If both are set, both are used for matching.
* `sgx_isv_prodid` is optional and defaults to `0`.
* `sgx_min_isv_svn` is optional and defaults to `0`.
* `sgx_allowed_tcb_levels` is optional and defaults to `Ok`.

## Authentication

- Client TEE generates a self-signed TLS client certificate
- Client TEE generates an attestation report, which includes the hash of the public key of the client certificate (in case of SGX, a sha256 sum of the public key)
- Client TEE fetches all collateral material via e.g. Intel DCAP ([`tee_qv_get_collateral`](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4cb5c8b81f126f9aa3ee921d7980a909a9bd676d/QuoteVerification/dcap_quoteverify/inc/sgx_dcap_quoteverify.h#L234-L238))
- Client TEE sends POST request with a TLS connection using the client certificate
  to Vault via the `${plugin}/login` endpoint with the name, attestation report and the attestation collateral material
- An optional challenge can be included in the POST request, which is then included in the attestation report of the vault response
```json
{
    "name": "The name of the TEE role to authenticate against.",
    "quote": "The quote Base64 encoded.",
    "collateral": "The collateral Json string encoded.",
    "challenge": "An optional challenge hex encoded."
}
```

The response contains the Vault token and, if a challenge was included,
the vault attestation report, which must contain the challenge bytes in the report_data of the quote.
```json
{
    "auth": {
        "client_token": "The Vault token.",
        "....": "...."
    },
    "data": {
        "quote": "The vault quote Base64 encoded.",
        "collateral": "The vault collateral Json string encoded."
    }
}
```

### Collateral Json encoding

See [sgx_ql_lib_common.h](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/4cb5c8b81f126f9aa3ee921d7980a909a9bd676d/QuoteGeneration/quote_wrapper/common/inc/sgx_ql_lib_common.h#L202-L227)

```json
{
    "major_version": uint16,
    "minor_version": uint16,
    "tee_type": uint32,
    "pck_crl_issuer_chain": []byte,
    "root_ca_crl": []byte,
    "pck_crl": []byte,
    "tcb_info_issuer_chain": []byte,
    "tcb_info": []byte,
    "qe_identity_issuer_chain": []byte,
    "qe_identity": []byte
}
```