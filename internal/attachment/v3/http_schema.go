package v3

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/zeebo/blake3"
)

const (
	attachmentHTTPPost uint64 = iota + 1
	attachmentHTTPPut
	attachmentHTTPGet
)

// AttachmentRoute is the one fixed v3 attachment route grammar. It is parsed
// from an unescaped URL path, before permit or operation redemption.
type AttachmentRoute struct {
	TransferID        [16]byte
	Operation         uint64
	ChunkIndex        uint64
	AttemptGeneration uint64
	httpMethod        uint64
	path              string
}

// ParseAttachmentRoute accepts only canonical v3 attachment paths and the
// exact method assigned by the protocol. It takes the escaped path verbatim;
// callers must reject URL queries, fragments, RawPath and content encodings
// before passing it here.
func ParseAttachmentRoute(method, path string) (AttachmentRoute, error) {
	if path == "" || strings.ContainsAny(path, "%?#\x00") {
		return AttachmentRoute{}, errors.New("invalid v3 attachment route")
	}
	methodID, ok := attachmentHTTPMethod(method)
	if !ok {
		return AttachmentRoute{}, errors.New("invalid v3 attachment method")
	}
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[0] != "" || parts[1] != "v3" || parts[2] != "attachments" {
		return AttachmentRoute{}, errors.New("invalid v3 attachment route")
	}
	transferID, err := parseAttachmentTransferID(parts[3])
	if err != nil {
		return AttachmentRoute{}, err
	}
	route := AttachmentRoute{TransferID: transferID, httpMethod: methodID, path: path}
	switch {
	case len(parts) == 5 && parts[4] == "source" && methodID == attachmentHTTPPost:
		route.Operation = permitOperationSourceInit
	case len(parts) == 7 && parts[4] == "source" && parts[5] == "chunks" && methodID == attachmentHTTPPut:
		index, err := parseAttachmentUint(parts[6])
		if err != nil {
			return AttachmentRoute{}, err
		}
		route.Operation, route.ChunkIndex = permitOperationSourceUpload, index
	case len(parts) == 5 && parts[4] == "offer" && methodID == attachmentHTTPPost:
		route.Operation = permitOperationOffer
	case len(parts) == 5 && parts[4] == "accept" && methodID == attachmentHTTPPost:
		route.Operation = permitOperationAccept
	case len(parts) == 7 && parts[4] == "attempts" && parts[6] == "begin" && methodID == attachmentHTTPPost:
		attempt, err := parseAttachmentUint(parts[5])
		if err != nil || attempt != 1 {
			return AttachmentRoute{}, errors.New("invalid v3 attachment attempt")
		}
		route.Operation, route.AttemptGeneration = permitOperationBegin, attempt
	case len(parts) == 6 && parts[4] == "chunks" && methodID == attachmentHTTPGet:
		index, err := parseAttachmentUint(parts[5])
		if err != nil {
			return AttachmentRoute{}, err
		}
		route.Operation, route.ChunkIndex = permitOperationDownload, index
	case len(parts) == 5 && parts[4] == "complete" && methodID == attachmentHTTPPost:
		route.Operation = permitOperationComplete
	case len(parts) == 5 && parts[4] == "cancel" && methodID == attachmentHTTPPost:
		route.Operation = permitOperationCancel
	case len(parts) == 5 && parts[4] == "outcome" && methodID == attachmentHTTPGet:
		route.Operation = permitOperationOutcome
	default:
		return AttachmentRoute{}, errors.New("invalid v3 attachment route")
	}
	return route, nil
}

// NewAttachmentOperationRequest derives the target from the parsed fixed
// route. A handler must never accept an arbitrary target, path or method as a
// substitute for this constructor. Download admission deliberately has no
// response ciphertext: the relay selects it only after permit and operation
// authorization inside its storage transaction. The actual HTTP handler
// additionally rejects URL normalization ambiguity before calling this
// function.
func NewAttachmentOperationRequest(method, path string, body, responseCiphertext []byte) (AttachmentRoute, OperationRequest, error) {
	route, err := ParseAttachmentRoute(method, path)
	if err != nil {
		return AttachmentRoute{}, OperationRequest{}, err
	}
	target, err := attachmentRouteTarget(route)
	if err != nil {
		return AttachmentRoute{}, OperationRequest{}, err
	}
	if route.Operation == permitOperationDownload || route.Operation == permitOperationOutcome {
		if len(body) != 0 || len(responseCiphertext) != 0 {
			return AttachmentRoute{}, OperationRequest{}, errors.New("v3 download request body is forbidden")
		}
		request, err := newOperationRecordRequest(route.httpMethod, path, target, nil)
		return route, request, err
	}
	if len(responseCiphertext) != 0 || !validAttachmentRequestBody(route.Operation, body) {
		return AttachmentRoute{}, OperationRequest{}, errors.New("invalid v3 attachment request body")
	}
	request, err := newOperationRecordRequest(route.httpMethod, path, target, body)
	return route, request, err
}

func validAttachmentRequestBody(operation uint64, body []byte) bool {
	switch operation {
	case permitOperationSourceInit:
		return len(body) > 0 && len(body) <= maxManifestEncodedBytes
	case permitOperationSourceUpload:
		return len(body) > 0
	case permitOperationOffer:
		return len(body) > 0 && len(body) <= maxOfferPayloadBytes
	case permitOperationAccept:
		return len(body) == 32
	case permitOperationBegin, permitOperationComplete, permitOperationCancel, permitOperationOutcome:
		return len(body) == 0
	default:
		return false
	}
}

// VerifyAttachmentRoute binds a parsed canonical route to the permit before
// redemption. Transfer, operation and attempt generation cannot come from an
// independently decoded target.
func VerifyAttachmentRoute(route AttachmentRoute, permit Permit) error {
	if route.TransferID != permit.TransferID || route.Operation != permit.Operation || route.httpMethod == 0 || route.path == "" {
		return errors.New("v3 route does not match permit")
	}
	switch route.Operation {
	case permitOperationBegin:
		if route.AttemptGeneration != 1 || permit.AttemptGeneration != route.AttemptGeneration {
			return errors.New("v3 route attempt does not match permit")
		}
	case permitOperationDownload, permitOperationComplete:
		if route.AttemptGeneration != 0 || permit.AttemptGeneration != 1 {
			return errors.New("v3 route attempt does not match permit")
		}
	default:
		if route.AttemptGeneration != 0 || permit.AttemptGeneration != 0 {
			return errors.New("v3 route attempt does not match permit")
		}
	}
	return nil
}

func verifyAttachmentRequestRoute(route AttachmentRoute, permit Permit, request OperationRequest) error {
	if request.method != route.httpMethod || request.path != route.path {
		return errors.New("v3 operation request route mismatch")
	}
	target, err := attachmentRouteTarget(route)
	if err != nil || !bytes.Equal(request.target, target) {
		return errors.New("v3 operation request route mismatch")
	}
	if route.Operation == permitOperationDownload || route.Operation == permitOperationOutcome {
		if len(request.body) != 0 || len(request.responseCiphertext) != 0 {
			return errors.New("invalid v3 download request body")
		}
		return nil
	}
	if len(request.responseCiphertext) != 0 || !validAttachmentRequestBody(route.Operation, request.body) {
		return errors.New("invalid v3 attachment request body")
	}
	if route.Operation == permitOperationSourceInit {
		manifest, err := DecodeManifest(request.body)
		if err != nil || !sourceInitPermitBinding(permit, manifest, request.body) {
			return errors.New("invalid v3 source-init permit body")
		}
	}
	if route.Operation == permitOperationOffer {
		if err := validateOfferPayloadForPermit(request.body, permit); err != nil {
			return err
		}
	}
	return nil
}

// sourceInitPermitBinding is syntax/binding validation only. The source-init
// handler must still call DecodeAndVerifySourceInit with its fresh directory
// resolver before reserving storage or redeeming the operation.
func sourceInitPermitBinding(permit Permit, manifest Manifest, raw []byte) bool {
	commitment := blake3.Sum256(raw)
	return commitment == permit.StagedManifestCommitment && manifest.Audience == permit.Audience &&
		manifest.TransferID == permit.TransferID && manifest.ConversationID == permit.ConversationID &&
		manifest.SenderDeviceID == permit.SenderDeviceID && manifest.SenderGeneration == permit.SenderGeneration &&
		manifest.RecipientDeviceID == permit.RecipientDeviceID && manifest.RecipientGeneration == permit.RecipientGeneration &&
		manifest.DirectoryHead == permit.DirectoryHead && manifest.MembershipCommitment == permit.MembershipCommitment &&
		manifest.RevocationEpoch == permit.RevocationEpoch && permit.ExpiresAt <= manifest.ExpiresAt
}

func attachmentHTTPMethod(method string) (uint64, bool) {
	switch method {
	case "POST":
		return attachmentHTTPPost, true
	case "PUT":
		return attachmentHTTPPut, true
	case "GET":
		return attachmentHTTPGet, true
	default:
		return 0, false
	}
}

func parseAttachmentTransferID(raw string) ([16]byte, error) {
	if len(raw) != 32 || raw != strings.ToLower(raw) {
		return [16]byte{}, errors.New("invalid v3 attachment transfer id")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return [16]byte{}, errors.New("invalid v3 attachment transfer id")
	}
	var id [16]byte
	copy(id[:], decoded)
	if id == [16]byte{} {
		return [16]byte{}, errors.New("invalid v3 attachment transfer id")
	}
	return id, nil
}

func parseAttachmentUint(raw string) (uint64, error) {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid v3 attachment integer")
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, errors.New("invalid v3 attachment integer")
	}
	return value, nil
}

func attachmentRouteTarget(route AttachmentRoute) ([]byte, error) {
	target := map[uint64]any{1: uint64(protocolVersion), 2: route.TransferID, 3: route.Operation}
	if route.Operation == permitOperationSourceUpload || route.Operation == permitOperationDownload {
		target[4] = route.ChunkIndex
	}
	if route.Operation == permitOperationBegin {
		target[5] = route.AttemptGeneration
	}
	return canonicalEncoding.Marshal(target)
}
