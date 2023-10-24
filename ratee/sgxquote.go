// SPDX-License-Identifier: MPL-2.0
// Copyright (c) Matter Labs

package ratee

// #cgo LDFLAGS: -lsgx_dcap_quoteverify -ldl
/*
#include <stdlib.h> // for malloc/free
#include <sgx_dcap_quoteverify.h>
#include <sgx_quote.h>

sgx_ql_qv_supplemental_t *allocSupp() { return (sgx_ql_qv_supplemental_t*) malloc(sizeof(sgx_ql_qv_supplemental_t)); }
void freeSupp(sgx_ql_qv_supplemental_t * * p) { free(p); }
*/
import "C"

import (
	"bytes"
	"encoding/binary"
	"errors"
	"os"
	"unsafe"
)

type TeeQvCollateral struct {
	MajorVersion          uint16 `json:"major_version"`
	MinorVersion          uint16 `json:"minor_version"`
	TeeType               uint32 `json:"tee_type"`
	PckCrlIssuerChain     []byte `json:"pck_crl_issuer_chain"`
	RootCaCrl             []byte `json:"root_ca_crl"`
	PckCrl                []byte `json:"pck_crl"`
	TcbInfoIssuerChain    []byte `json:"tcb_info_issuer_chain"`
	TcbInfo               []byte `json:"tcb_info"`
	QeIdentityIssuerChain []byte `json:"qe_identity_issuer_chain"`
	QeIdentity            []byte `json:"qe_identity"`
}

type Quote struct {
	Version    [2]byte  `json:"version"`
	KeyType    [2]byte  `json:"key_type"`
	Reserved   [4]byte  `json:"reserved"`
	QeSvn      [2]byte  `json:"qe_svn"`
	PceSvn     [2]byte  `json:"pce_svn"`
	QeVendorId [16]byte `json:"qe_vendor_id"`
	UserData   [20]byte `json:"user_data"`
	ReportBody struct {
		Cpusvn     [16]byte `json:"cpusvn"`
		Miscselect [4]byte  `json:"miscselect"`
		Reserved1  [28]byte `json:"reserved1"`
		Features   [8]byte  `json:"features"`
		Xfrm       [8]byte  `json:"xfrm"`
		MrEnclave  [32]byte `json:"mrenclave"`
		Reserved2  [32]byte `json:"reserved2"`
		MrSigner   [32]byte `json:"mrsigner"`
		Reserved3  [96]byte `json:"reserved3"`
		IsvProdid  [2]byte  `json:"isv_prodid"`
		IsvSvn     [2]byte  `json:"isv_svn"`
		Reserved4  [60]byte `json:"reserved4"`
		ReportData [64]byte `json:"reportdata"`
	} `json:"report_body"`
}

type QuoteVerificationResult struct {
	VerificationResult     SgxQlQvResult
	CollateralExpired      bool
	EarliestExpirationDate int64
	Advisory               string
	Quote                  Quote
}

// convertCollateral converts TeeQvCollateral to sgx_ql_qve_collateral_t
func convertQveCollateral(coll C.sgx_ql_qve_collateral_t) TeeQvCollateral {
	var data = TeeQvCollateral{
		TeeType:               uint32(coll.tee_type),
		PckCrlIssuerChain:     C.GoBytes(unsafe.Pointer(coll.pck_crl_issuer_chain), C.int(coll.pck_crl_issuer_chain_size)),
		RootCaCrl:             C.GoBytes(unsafe.Pointer(coll.root_ca_crl), C.int(coll.root_ca_crl_size)),
		PckCrl:                C.GoBytes(unsafe.Pointer(coll.pck_crl), C.int(coll.pck_crl_size)),
		TcbInfoIssuerChain:    C.GoBytes(unsafe.Pointer(coll.tcb_info_issuer_chain), C.int(coll.tcb_info_issuer_chain_size)),
		TcbInfo:               C.GoBytes(unsafe.Pointer(coll.tcb_info), C.int(coll.tcb_info_size)),
		QeIdentityIssuerChain: C.GoBytes(unsafe.Pointer(coll.qe_identity_issuer_chain), C.int(coll.qe_identity_issuer_chain_size)),
		QeIdentity:            C.GoBytes(unsafe.Pointer(coll.qe_identity), C.int(coll.qe_identity_size)),
	}

	// Hack needed due to unnamed union and struct at the beginning
	var pver = (*[2]uint16)(unsafe.Pointer(&coll))
	data.MajorVersion = pver[0]
	data.MinorVersion = pver[1]

	return data
}

// convertCollateral converts TeeQvCollateral to sgx_ql_qve_collateral_t
func convertCollateral(coll TeeQvCollateral) C.sgx_ql_qve_collateral_t {
	var data = C.sgx_ql_qve_collateral_t{
		tee_type:                      C.uint32_t(coll.TeeType),
		pck_crl_issuer_chain:          (*C.char)(C.CBytes(coll.PckCrlIssuerChain)),
		pck_crl_issuer_chain_size:     C.uint32_t(len(coll.PckCrlIssuerChain)),
		root_ca_crl:                   (*C.char)(C.CBytes(coll.RootCaCrl)),
		root_ca_crl_size:              C.uint32_t(len(coll.RootCaCrl)),
		pck_crl:                       (*C.char)(C.CBytes(coll.PckCrl)),
		pck_crl_size:                  C.uint32_t(len(coll.PckCrl)),
		tcb_info_issuer_chain:         (*C.char)(C.CBytes(coll.TcbInfoIssuerChain)),
		tcb_info_issuer_chain_size:    C.uint32_t(len(coll.TcbInfoIssuerChain)),
		tcb_info:                      (*C.char)(C.CBytes(coll.TcbInfo)),
		tcb_info_size:                 C.uint32_t(len(coll.TcbInfo)),
		qe_identity_issuer_chain:      (*C.char)(C.CBytes(coll.QeIdentityIssuerChain)),
		qe_identity_issuer_chain_size: C.uint32_t(len(coll.QeIdentityIssuerChain)),
		qe_identity:                   (*C.char)(C.CBytes(coll.QeIdentity)),
		qe_identity_size:              C.uint32_t(len(coll.QeIdentity)),
	}

	// Hack needed due to unnamed union and struct at the beginning
	var pver = (*[2]uint16)(unsafe.Pointer(&data))
	pver[0] = coll.MajorVersion
	pver[1] = coll.MinorVersion

	return data
}

type SgxQlQvResult uint32

const (
	SgxQlQvResultOk                         = SgxQlQvResult(C.SGX_QL_QV_RESULT_OK)
	SgxQlQvResultConfigNeeded               = SgxQlQvResult(C.SGX_QL_QV_RESULT_CONFIG_NEEDED)
	SgxQlQvResultOutOfDate                  = SgxQlQvResult(C.SGX_QL_QV_RESULT_OUT_OF_DATE)
	SgxQlQvResultOutOfDateConfigNeeded      = SgxQlQvResult(C.SGX_QL_QV_RESULT_OUT_OF_DATE_CONFIG_NEEDED)
	SgxQlQvResultInvalidSignature           = SgxQlQvResult(C.SGX_QL_QV_RESULT_INVALID_SIGNATURE)
	SgxQlQvResultRevoked                    = SgxQlQvResult(C.SGX_QL_QV_RESULT_REVOKED)
	SgxQlQvResultUnspecified                = SgxQlQvResult(C.SGX_QL_QV_RESULT_UNSPECIFIED)
	SgxQlQvResultSwHardeningNeeded          = SgxQlQvResult(C.SGX_QL_QV_RESULT_SW_HARDENING_NEEDED)
	SgxQlQvResultConfigAndSwHardeningNeeded = SgxQlQvResult(C.SGX_QL_QV_RESULT_CONFIG_AND_SW_HARDENING_NEEDED)
)

var (
	// ErrEmptyReport is returned by VerifyRemoteReport if reportBytes is empty.
	ErrEmptyReport                               = errors.New("empty report")
	ErrSgxQlErrorUnexpected                      = errors.New("SGX_QL_ERROR_UNEXPECTED")
	ErrSgxQlErrorInvalidParameter                = errors.New("SGX_QL_ERROR_INVALID_PARAMETER")
	ErrSgxQlErrorOutOfMemory                     = errors.New("SGX_QL_ERROR_OUT_OF_MEMORY")
	ErrSgxQlErrorEcdsaIdMismatch                 = errors.New("SGX_QL_ERROR_ECDSA_ID_MISMATCH")
	ErrSgxQlPathnameBufferOverflowError          = errors.New("SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR")
	ErrSgxQlFileAccessError                      = errors.New("SGX_QL_FILE_ACCESS_ERROR")
	ErrSgxQlErrorStoredKey                       = errors.New("SGX_QL_ERROR_STORED_KEY")
	ErrSgxQlErrorPubKeyIdMismatch                = errors.New("SGX_QL_ERROR_PUB_KEY_ID_MISMATCH")
	ErrSgxQlErrorInvalidPceSigScheme             = errors.New("SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME")
	ErrSgxQlAttKeyBlobError                      = errors.New("SGX_QL_ATT_KEY_BLOB_ERROR")
	ErrSgxQlUnsupportedAttKeyId                  = errors.New("SGX_QL_UNSUPPORTED_ATT_KEY_ID")
	ErrSgxQlUnsupportedLoadingPolicy             = errors.New("SGX_QL_UNSUPPORTED_LOADING_POLICY")
	ErrSgxQlInterfaceUnavailable                 = errors.New("SGX_QL_INTERFACE_UNAVAILABLE")
	ErrSgxQlPlatformLibUnavailable               = errors.New("SGX_QL_PLATFORM_LIB_UNAVAILABLE")
	ErrSgxQlAttKeyNotInitialized                 = errors.New("SGX_QL_ATT_KEY_NOT_INITIALIZED")
	ErrSgxQlAttKeyCertDataInvalid                = errors.New("SGX_QL_ATT_KEY_CERT_DATA_INVALID")
	ErrSgxQlNoPlatformCertData                   = errors.New("SGX_QL_NO_PLATFORM_CERT_DATA")
	ErrSgxQlOutOfEpc                             = errors.New("SGX_QL_OUT_OF_EPC")
	ErrSgxQlErrorReport                          = errors.New("SGX_QL_ERROR_REPORT")
	ErrSgxQlEnclaveLost                          = errors.New("SGX_QL_ENCLAVE_LOST")
	ErrSgxQlInvalidReport                        = errors.New("SGX_QL_INVALID_REPORT")
	ErrSgxQlEnclaveLoadError                     = errors.New("SGX_QL_ENCLAVE_LOAD_ERROR")
	ErrSgxQlUnableToGenerateQeReport             = errors.New("SGX_QL_UNABLE_TO_GENERATE_QE_REPORT")
	ErrSgxQlKeyCertifcationError                 = errors.New("SGX_QL_KEY_CERTIFCATION_ERROR")
	ErrSgxQlNetworkError                         = errors.New("SGX_QL_NETWORK_ERROR")
	ErrSgxQlMessageError                         = errors.New("SGX_QL_MESSAGE_ERROR")
	ErrSgxQlNoQuoteCollateralData                = errors.New("SGX_QL_NO_QUOTE_COLLATERAL_DATA")
	ErrSgxQlQuoteCertificationDataUnsupported    = errors.New("SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED")
	ErrSgxQlQuoteFormatUnsupported               = errors.New("SGX_QL_QUOTE_FORMAT_UNSUPPORTED")
	ErrSgxQlUnableToGenerateReport               = errors.New("SGX_QL_UNABLE_TO_GENERATE_REPORT")
	ErrSgxQlQeReportInvalidSignature             = errors.New("SGX_QL_QE_REPORT_INVALID_SIGNATURE")
	ErrSgxQlQeReportUnsupportedFormat            = errors.New("SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT")
	ErrSgxQlPckCertUnsupportedFormat             = errors.New("SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT")
	ErrSgxQlPckCertChainError                    = errors.New("SGX_QL_PCK_CERT_CHAIN_ERROR")
	ErrSgxQlTcbinfoUnsupportedFormat             = errors.New("SGX_QL_TCBINFO_UNSUPPORTED_FORMAT")
	ErrSgxQlTcbinfoMismatch                      = errors.New("SGX_QL_TCBINFO_MISMATCH")
	ErrSgxQlQeidentityUnsupportedFormat          = errors.New("SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT")
	ErrSgxQlQeidentityMismatch                   = errors.New("SGX_QL_QEIDENTITY_MISMATCH")
	ErrSgxQlTcbOutOfDate                         = errors.New("SGX_QL_TCB_OUT_OF_DATE")
	ErrSgxQlTcbOutOfDateConfigurationNeeded      = errors.New("SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED")
	ErrSgxQlSgxEnclaveIdentityOutOfDate          = errors.New("SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE")
	ErrSgxQlSgxEnclaveReportIsvsvnOutOfDate      = errors.New("SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE")
	ErrSgxQlQeIdentityOutOfDate                  = errors.New("SGX_QL_QE_IDENTITY_OUT_OF_DATE")
	ErrSgxQlSgxTcbInfoExpired                    = errors.New("SGX_QL_SGX_TCB_INFO_EXPIRED")
	ErrSgxQlSgxPckCertChainExpired               = errors.New("SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED")
	ErrSgxQlSgxCrlExpired                        = errors.New("SGX_QL_SGX_CRL_EXPIRED")
	ErrSgxQlSgxSigningCertChainExpired           = errors.New("SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED")
	ErrSgxQlSgxEnclaveIdentityExpired            = errors.New("SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED")
	ErrSgxQlPckRevoked                           = errors.New("SGX_QL_PCK_REVOKED")
	ErrSgxQlTcbRevoked                           = errors.New("SGX_QL_TCB_REVOKED")
	ErrSgxQlTcbConfigurationNeeded               = errors.New("SGX_QL_TCB_CONFIGURATION_NEEDED")
	ErrSgxQlUnableToGetCollateral                = errors.New("SGX_QL_UNABLE_TO_GET_COLLATERAL")
	ErrSgxQlErrorInvalidPrivilege                = errors.New("SGX_QL_ERROR_INVALID_PRIVILEGE")
	ErrSgxQlNoQveIdentityData                    = errors.New("SGX_QL_NO_QVE_IDENTITY_DATA")
	ErrSgxQlCrlUnsupportedFormat                 = errors.New("SGX_QL_CRL_UNSUPPORTED_FORMAT")
	ErrSgxQlQeidentityChainError                 = errors.New("SGX_QL_QEIDENTITY_CHAIN_ERROR")
	ErrSgxQlTcbinfoChainError                    = errors.New("SGX_QL_TCBINFO_CHAIN_ERROR")
	ErrSgxQlErrorQvlQveMismatch                  = errors.New("SGX_QL_ERROR_QVL_QVE_MISMATCH")
	ErrSgxQlTcbSwHardeningNeeded                 = errors.New("SGX_QL_TCB_SW_HARDENING_NEEDED")
	ErrSgxQlTcbConfigurationAndSwHardeningNeeded = errors.New("SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED")
	ErrSgxQlUnsupportedMode                      = errors.New("SGX_QL_UNSUPPORTED_MODE")
	ErrSgxQlNoDevice                             = errors.New("SGX_QL_NO_DEVICE")
	ErrSgxQlServiceUnavailable                   = errors.New("SGX_QL_SERVICE_UNAVAILABLE")
	ErrSgxQlNetworkFailure                       = errors.New("SGX_QL_NETWORK_FAILURE")
	ErrSgxQlServiceTimeout                       = errors.New("SGX_QL_SERVICE_TIMEOUT")
	ErrSgxQlErrorBusy                            = errors.New("SGX_QL_ERROR_BUSY")
	ErrSgxQlUnknownMessageResponse               = errors.New("SGX_QL_UNKNOWN_MESSAGE_RESPONSE")
	ErrSgxQlPersistentStorageError               = errors.New("SGX_QL_PERSISTENT_STORAGE_ERROR")
	ErrSgxQlErrorMessageParsingError             = errors.New("SGX_QL_ERROR_MESSAGE_PARSING_ERROR")
	ErrSgxQlPlatformUnknown                      = errors.New("SGX_QL_PLATFORM_UNKNOWN")
	ErrSgxQlUnknownApiVersion                    = errors.New("SGX_QL_UNKNOWN_API_VERSION")
	ErrSgxQlCertsUnavailable                     = errors.New("SGX_QL_CERTS_UNAVAILABLE")
	ErrSgxQlQveidentityMismatch                  = errors.New("SGX_QL_QVEIDENTITY_MISMATCH")
	ErrSgxQlQveOutOfDate                         = errors.New("SGX_QL_QVE_OUT_OF_DATE")
	ErrSgxQlPswNotAvailable                      = errors.New("SGX_QL_PSW_NOT_AVAILABLE")
	ErrSgxQlCollateralVersionNotSupported        = errors.New("SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED")
	ErrSgxQlTdxModuleMismatch                    = errors.New("SGX_QL_TDX_MODULE_MISMATCH")
	ErrSgxQlQeidentityNotFound                   = errors.New("SGX_QL_QEIDENTITY_NOT_FOUND")
	ErrSgxQlTcbinfoNotFound                      = errors.New("SGX_QL_TCBINFO_NOT_FOUND")
	ErrSgxQlInternalServerError                  = errors.New("SGX_QL_INTERNAL_SERVER_ERROR")
	ErrSgxQlSupplementalDataVersionNotSupported  = errors.New("SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED")
	ErrSgxQlRootCaUntrusted                      = errors.New("SGX_QL_ROOT_CA_UNTRUSTED")
	ErrSgxQlTcbNotSupported                      = errors.New("SGX_QL_TCB_NOT_SUPPORTED")
)

// convert an SGX quote library error to a go error
func sgx2Error(err uint32) error {
	switch err {
	case C.SGX_QL_ERROR_UNEXPECTED:
		return ErrSgxQlErrorUnexpected
	case C.SGX_QL_ERROR_INVALID_PARAMETER:
		return ErrSgxQlErrorInvalidParameter
	case C.SGX_QL_ERROR_OUT_OF_MEMORY:
		return ErrSgxQlErrorOutOfMemory
	case C.SGX_QL_ERROR_ECDSA_ID_MISMATCH:
		return ErrSgxQlErrorEcdsaIdMismatch
	case C.SGX_QL_PATHNAME_BUFFER_OVERFLOW_ERROR:
		return ErrSgxQlPathnameBufferOverflowError
	case C.SGX_QL_FILE_ACCESS_ERROR:
		return ErrSgxQlFileAccessError
	case C.SGX_QL_ERROR_STORED_KEY:
		return ErrSgxQlErrorStoredKey
	case C.SGX_QL_ERROR_PUB_KEY_ID_MISMATCH:
		return ErrSgxQlErrorPubKeyIdMismatch
	case C.SGX_QL_ERROR_INVALID_PCE_SIG_SCHEME:
		return ErrSgxQlErrorInvalidPceSigScheme
	case C.SGX_QL_ATT_KEY_BLOB_ERROR:
		return ErrSgxQlAttKeyBlobError
	case C.SGX_QL_UNSUPPORTED_ATT_KEY_ID:
		return ErrSgxQlUnsupportedAttKeyId
	case C.SGX_QL_UNSUPPORTED_LOADING_POLICY:
		return ErrSgxQlUnsupportedLoadingPolicy
	case C.SGX_QL_INTERFACE_UNAVAILABLE:
		return ErrSgxQlInterfaceUnavailable
	case C.SGX_QL_PLATFORM_LIB_UNAVAILABLE:
		return ErrSgxQlPlatformLibUnavailable
	case C.SGX_QL_ATT_KEY_NOT_INITIALIZED:
		return ErrSgxQlAttKeyNotInitialized
	case C.SGX_QL_ATT_KEY_CERT_DATA_INVALID:
		return ErrSgxQlAttKeyCertDataInvalid
	case C.SGX_QL_NO_PLATFORM_CERT_DATA:
		return ErrSgxQlNoPlatformCertData
	case C.SGX_QL_OUT_OF_EPC:
		return ErrSgxQlOutOfEpc
	case C.SGX_QL_ERROR_REPORT:
		return ErrSgxQlErrorReport
	case C.SGX_QL_ENCLAVE_LOST:
		return ErrSgxQlEnclaveLost
	case C.SGX_QL_INVALID_REPORT:
		return ErrSgxQlInvalidReport
	case C.SGX_QL_ENCLAVE_LOAD_ERROR:
		return ErrSgxQlEnclaveLoadError
	case C.SGX_QL_UNABLE_TO_GENERATE_QE_REPORT:
		return ErrSgxQlUnableToGenerateQeReport
	case C.SGX_QL_KEY_CERTIFCATION_ERROR:
		return ErrSgxQlKeyCertifcationError
	case C.SGX_QL_NETWORK_ERROR:
		return ErrSgxQlNetworkError
	case C.SGX_QL_MESSAGE_ERROR:
		return ErrSgxQlMessageError
	case C.SGX_QL_NO_QUOTE_COLLATERAL_DATA:
		return ErrSgxQlNoQuoteCollateralData
	case C.SGX_QL_QUOTE_CERTIFICATION_DATA_UNSUPPORTED:
		return ErrSgxQlQuoteCertificationDataUnsupported
	case C.SGX_QL_QUOTE_FORMAT_UNSUPPORTED:
		return ErrSgxQlQuoteFormatUnsupported
	case C.SGX_QL_UNABLE_TO_GENERATE_REPORT:
		return ErrSgxQlUnableToGenerateReport
	case C.SGX_QL_QE_REPORT_INVALID_SIGNATURE:
		return ErrSgxQlQeReportInvalidSignature
	case C.SGX_QL_QE_REPORT_UNSUPPORTED_FORMAT:
		return ErrSgxQlQeReportUnsupportedFormat
	case C.SGX_QL_PCK_CERT_UNSUPPORTED_FORMAT:
		return ErrSgxQlPckCertUnsupportedFormat
	case C.SGX_QL_PCK_CERT_CHAIN_ERROR:
		return ErrSgxQlPckCertChainError
	case C.SGX_QL_TCBINFO_UNSUPPORTED_FORMAT:
		return ErrSgxQlTcbinfoUnsupportedFormat
	case C.SGX_QL_TCBINFO_MISMATCH:
		return ErrSgxQlTcbinfoMismatch
	case C.SGX_QL_QEIDENTITY_UNSUPPORTED_FORMAT:
		return ErrSgxQlQeidentityUnsupportedFormat
	case C.SGX_QL_QEIDENTITY_MISMATCH:
		return ErrSgxQlQeidentityMismatch
	case C.SGX_QL_TCB_OUT_OF_DATE:
		return ErrSgxQlTcbOutOfDate
	case C.SGX_QL_TCB_OUT_OF_DATE_CONFIGURATION_NEEDED:
		return ErrSgxQlTcbOutOfDateConfigurationNeeded
	case C.SGX_QL_SGX_ENCLAVE_IDENTITY_OUT_OF_DATE:
		return ErrSgxQlSgxEnclaveIdentityOutOfDate
	case C.SGX_QL_SGX_ENCLAVE_REPORT_ISVSVN_OUT_OF_DATE:
		return ErrSgxQlSgxEnclaveReportIsvsvnOutOfDate
	case C.SGX_QL_QE_IDENTITY_OUT_OF_DATE:
		return ErrSgxQlQeIdentityOutOfDate
	case C.SGX_QL_SGX_TCB_INFO_EXPIRED:
		return ErrSgxQlSgxTcbInfoExpired
	case C.SGX_QL_SGX_PCK_CERT_CHAIN_EXPIRED:
		return ErrSgxQlSgxPckCertChainExpired
	case C.SGX_QL_SGX_CRL_EXPIRED:
		return ErrSgxQlSgxCrlExpired
	case C.SGX_QL_SGX_SIGNING_CERT_CHAIN_EXPIRED:
		return ErrSgxQlSgxSigningCertChainExpired
	case C.SGX_QL_SGX_ENCLAVE_IDENTITY_EXPIRED:
		return ErrSgxQlSgxEnclaveIdentityExpired
	case C.SGX_QL_PCK_REVOKED:
		return ErrSgxQlPckRevoked
	case C.SGX_QL_TCB_REVOKED:
		return ErrSgxQlTcbRevoked
	case C.SGX_QL_TCB_CONFIGURATION_NEEDED:
		return ErrSgxQlTcbConfigurationNeeded
	case C.SGX_QL_UNABLE_TO_GET_COLLATERAL:
		return ErrSgxQlUnableToGetCollateral
	case C.SGX_QL_ERROR_INVALID_PRIVILEGE:
		return ErrSgxQlErrorInvalidPrivilege
	case C.SGX_QL_NO_QVE_IDENTITY_DATA:
		return ErrSgxQlNoQveIdentityData
	case C.SGX_QL_CRL_UNSUPPORTED_FORMAT:
		return ErrSgxQlCrlUnsupportedFormat
	case C.SGX_QL_QEIDENTITY_CHAIN_ERROR:
		return ErrSgxQlQeidentityChainError
	case C.SGX_QL_TCBINFO_CHAIN_ERROR:
		return ErrSgxQlTcbinfoChainError
	case C.SGX_QL_ERROR_QVL_QVE_MISMATCH:
		return ErrSgxQlErrorQvlQveMismatch
	case C.SGX_QL_TCB_SW_HARDENING_NEEDED:
		return ErrSgxQlTcbSwHardeningNeeded
	case C.SGX_QL_TCB_CONFIGURATION_AND_SW_HARDENING_NEEDED:
		return ErrSgxQlTcbConfigurationAndSwHardeningNeeded
	case C.SGX_QL_UNSUPPORTED_MODE:
		return ErrSgxQlUnsupportedMode
	case C.SGX_QL_NO_DEVICE:
		return ErrSgxQlNoDevice
	case C.SGX_QL_SERVICE_UNAVAILABLE:
		return ErrSgxQlServiceUnavailable
	case C.SGX_QL_NETWORK_FAILURE:
		return ErrSgxQlNetworkFailure
	case C.SGX_QL_SERVICE_TIMEOUT:
		return ErrSgxQlServiceTimeout
	case C.SGX_QL_ERROR_BUSY:
		return ErrSgxQlErrorBusy
	case C.SGX_QL_UNKNOWN_MESSAGE_RESPONSE:
		return ErrSgxQlUnknownMessageResponse
	case C.SGX_QL_PERSISTENT_STORAGE_ERROR:
		return ErrSgxQlPersistentStorageError
	case C.SGX_QL_ERROR_MESSAGE_PARSING_ERROR:
		return ErrSgxQlErrorMessageParsingError
	case C.SGX_QL_PLATFORM_UNKNOWN:
		return ErrSgxQlPlatformUnknown
	case C.SGX_QL_UNKNOWN_API_VERSION:
		return ErrSgxQlUnknownApiVersion
	case C.SGX_QL_CERTS_UNAVAILABLE:
		return ErrSgxQlCertsUnavailable
	case C.SGX_QL_QVEIDENTITY_MISMATCH:
		return ErrSgxQlQveidentityMismatch
	case C.SGX_QL_QVE_OUT_OF_DATE:
		return ErrSgxQlQveOutOfDate
	case C.SGX_QL_PSW_NOT_AVAILABLE:
		return ErrSgxQlPswNotAvailable
	case C.SGX_QL_COLLATERAL_VERSION_NOT_SUPPORTED:
		return ErrSgxQlCollateralVersionNotSupported
	case C.SGX_QL_TDX_MODULE_MISMATCH:
		return ErrSgxQlTdxModuleMismatch
	case C.SGX_QL_QEIDENTITY_NOT_FOUND:
		return ErrSgxQlQeidentityNotFound
	case C.SGX_QL_TCBINFO_NOT_FOUND:
		return ErrSgxQlTcbinfoNotFound
	case C.SGX_QL_INTERNAL_SERVER_ERROR:
		return ErrSgxQlInternalServerError
	case C.SGX_QL_SUPPLEMENTAL_DATA_VERSION_NOT_SUPPORTED:
		return ErrSgxQlSupplementalDataVersionNotSupported
	case C.SGX_QL_ROOT_CA_UNTRUSTED:
		return ErrSgxQlRootCaUntrusted
	case C.SGX_QL_TCB_NOT_SUPPORTED:
		return ErrSgxQlTcbNotSupported
	}
	return ErrSgxQlErrorUnexpected
}

func verifyRemoteReportSGXCollateral(reportBytes []byte, pQuoteCollateral *C.sgx_ql_qve_collateral_t, expirationCheckDate int64) (*QuoteVerificationResult, error) {
	if len(reportBytes) == 0 {
		return nil, ErrEmptyReport
	}

	var collateralExpirationStatus uint32
	var quoteVerificationResult uint32

	var pSuppData = C.allocSupp()
	var suppDataDesc = C.tee_supp_data_descriptor_t{
		major_version: 0,
		data_size:     C.uint(unsafe.Sizeof(C.sgx_ql_qv_supplemental_t{})),
		p_data:        (*C.uchar)(unsafe.Pointer(pSuppData)),
	}

	var pReportBytes = C.CBytes(reportBytes)

	res := uint32(C.tee_verify_quote(
		(*C.uint8_t)(pReportBytes),
		C.uint32_t(len(reportBytes)),
		(*C.uint8_t)(unsafe.Pointer(pQuoteCollateral)),
		C.time_t(expirationCheckDate),
		(*C.uint32_t)(&collateralExpirationStatus),
		(*C.sgx_ql_qv_result_t)(&quoteVerificationResult),
		nil,
		&suppDataDesc,
	))

	if res != C.SGX_QL_SUCCESS {
		return nil, sgx2Error(res)
	}

	var quote = Quote{}
	var byteReader = bytes.NewReader(reportBytes)
	err := binary.Read(byteReader, binary.BigEndian, &quote)
	if err != nil {
		panic(err)
	}

	var ret = QuoteVerificationResult{
		VerificationResult:     SgxQlQvResult(quoteVerificationResult),
		CollateralExpired:      collateralExpirationStatus != 0,
		EarliestExpirationDate: int64(pSuppData.earliest_expiration_date),
		Quote:                  quote,
	}

	return &ret, nil
}

// SgxVerifyRemoteReport verifies the SGX attestation report.
// It needs to connect to servers to collect the collateral material.
func SgxVerifyRemoteReport(reportBytes []byte, expirationCheckDate int64) (*QuoteVerificationResult, error) {
	if len(reportBytes) == 0 {
		return nil, ErrEmptyReport
	}

	var pQuoteCollateral *C.uint8_t = nil
	var collateralSize C.uint32_t
	res := uint32(C.tee_qv_get_collateral(
		(*C.uint8_t)(&reportBytes[0]),
		C.uint32_t(len(reportBytes)),
		(**C.uint8_t)(&pQuoteCollateral),
		(*C.uint32_t)(&collateralSize),
	))

	defer C.tee_qv_free_collateral(pQuoteCollateral)

	if res != C.SGX_QL_SUCCESS {
		return nil, sgx2Error(res)
	}

	return verifyRemoteReportSGXCollateral(reportBytes, (*C.sgx_ql_qve_collateral_t)(unsafe.Pointer(pQuoteCollateral)), expirationCheckDate)
}

// SgxVerifyRemoteReportCollateral verifies the report along with the collateral material.
// It does not need to start an SGX enclave, nor does it need to connect to any server.
func SgxVerifyRemoteReportCollateral(reportBytes []byte, collateral TeeQvCollateral, expirationCheckDate int64) (*QuoteVerificationResult, error) {
	var quoteCollateral = convertCollateral(collateral)

	return verifyRemoteReportSGXCollateral(reportBytes, &quoteCollateral, expirationCheckDate)
}

func SgxGetCollateral(reportBytes []byte) (*TeeQvCollateral, error) {
	var pQuoteCollateral *C.uint8_t = nil
	var collateralSize C.uint32_t
	res := uint32(C.tee_qv_get_collateral(
		(*C.uint8_t)(&reportBytes[0]),
		C.uint32_t(len(reportBytes)),
		(**C.uint8_t)(&pQuoteCollateral),
		(*C.uint32_t)(&collateralSize),
	))

	defer C.tee_qv_free_collateral(pQuoteCollateral)

	if res != C.SGX_QL_SUCCESS {
		return nil, sgx2Error(res)
	}

	coll := convertQveCollateral(*(*C.sgx_ql_qve_collateral_t)(unsafe.Pointer(pQuoteCollateral)))

	return &coll, nil
}

func sgxGramineGetQuote(reportData []byte) ([]byte, error) {
	// open "/dev/attestation/user_report_data" and write reportData
	if err := os.WriteFile("/dev/attestation/user_report_data", reportData, 0666); err != nil {
		return nil, err
	}

	// open "/dev/attestation/quote" and read quote
	quote, err := os.ReadFile("/dev/attestation/quote")
	if err != nil {
		return nil, err
	}
	return quote, nil
}

func SgxGetQuote(reportData []byte) ([]byte, error) {
	if len(reportData) > 64 {
		reportData = reportData[:64]
	}
	if len(reportData) < 64 {
		reportData = append(reportData, make([]byte, 64-len(reportData))...)
	}
	// only support Gramine for now

	// check if "/dev/attestation/user_report_data" and "/dev/attestation/quote" exist
	if _, err := os.Stat("/dev/attestation/user_report_data"); err != nil {
		return nil, err
	}
	if _, err := os.Stat("/dev/attestation/quote"); err != nil {
		return nil, err
	}

	return sgxGramineGetQuote(reportData)
}
