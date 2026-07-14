package v2

import (
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	attachmentHTTPPost uint64 = iota + 1
	attachmentHTTPPut
	attachmentHTTPGet
)

// AttachmentRoute is a parsed fixed attachment v2 route. A zero Action means
// the route handles immutable ciphertext rather than a transfer transition.
type AttachmentRoute struct {
	TransferID        [16]byte
	Operation         uint64
	Action            TransferAction
	ChunkIndex        uint64
	AttemptGeneration uint64
	httpMethod        uint64
}

// ParseAttachmentRoute accepts only canonical v2 attachment paths and their
// fixed HTTP method. It takes the escaped path verbatim: callers must not pass
// a decoded path or a URL containing a query or fragment.
func ParseAttachmentRoute(method, path string) (AttachmentRoute, error) {
	if strings.ContainsAny(path, "?#\x00") || path == "" {
		return AttachmentRoute{}, errors.New("invalid attachment route")
	}
	methodID, ok := attachmentHTTPMethod(method)
	if !ok {
		return AttachmentRoute{}, errors.New("invalid attachment method")
	}
	parts := strings.Split(path, "/")
	if len(parts) < 5 || parts[0] != "" || parts[1] != "v2" || parts[2] != "attachments" {
		return AttachmentRoute{}, errors.New("invalid attachment route")
	}
	transferID, err := parseAttachmentTransferID(parts[3])
	if err != nil {
		return AttachmentRoute{}, err
	}
	route := AttachmentRoute{TransferID: transferID, httpMethod: methodID}
	switch {
	case len(parts) == 5 && parts[4] == "offer" && methodID == attachmentHTTPPost:
		route.Operation, route.Action = PermitOperationOffer, TransferActionOffer
	case len(parts) == 5 && parts[4] == "accept" && methodID == attachmentHTTPPost:
		route.Operation, route.Action = PermitOperationAccept, TransferActionAccept
	case len(parts) == 5 && parts[4] == "complete" && methodID == attachmentHTTPPost:
		route.Operation, route.Action = PermitOperationComplete, TransferActionComplete
	case len(parts) == 6 && parts[4] == "chunks":
		index, err := parseAttachmentUint(parts[5])
		if err != nil {
			return AttachmentRoute{}, err
		}
		route.ChunkIndex = index
		switch methodID {
		case attachmentHTTPPut:
			route.Operation = PermitOperationUpload
		case attachmentHTTPGet:
			route.Operation = PermitOperationDownload
		default:
			return AttachmentRoute{}, errors.New("invalid attachment method")
		}
	case len(parts) == 7 && parts[4] == "attempts" && parts[6] == "begin" && methodID == attachmentHTTPPost:
		attempt, err := parseAttachmentUint(parts[5])
		if err != nil || attempt == 0 {
			return AttachmentRoute{}, errors.New("invalid attachment attempt")
		}
		route.Operation, route.Action, route.AttemptGeneration = PermitOperationSignal, TransferActionBegin, attempt
	default:
		return AttachmentRoute{}, errors.New("invalid attachment route")
	}
	return route, nil
}

// NewAttachmentOperationRequest derives the permit-bound operation request
// from an exact parsed route. responseCiphertext is accepted only for a GET
// download and must be the immutable chunk selected by relay storage.
func NewAttachmentOperationRequest(method, path string, body, responseCiphertext []byte) (AttachmentRoute, OperationRequest, error) {
	route, err := ParseAttachmentRoute(method, path)
	if err != nil {
		return AttachmentRoute{}, OperationRequest{}, err
	}
	target, err := attachmentRouteTarget(route)
	if err != nil {
		return AttachmentRoute{}, OperationRequest{}, err
	}
	if route.Operation == PermitOperationDownload {
		if len(body) != 0 {
			return AttachmentRoute{}, OperationRequest{}, errors.New("download request body is forbidden")
		}
		request, err := NewDownloadOperationRequest(route.httpMethod, path, target, responseCiphertext)
		return route, request, err
	}
	if len(responseCiphertext) != 0 || (route.Operation == PermitOperationUpload && len(body) == 0) {
		return AttachmentRoute{}, OperationRequest{}, errors.New("invalid attachment request body")
	}
	request, err := NewOperationRecordRequest(route.httpMethod, path, target, body)
	return route, request, err
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
		return [16]byte{}, errors.New("invalid attachment transfer id")
	}
	decoded, err := hex.DecodeString(raw)
	if err != nil || len(decoded) != 16 {
		return [16]byte{}, errors.New("invalid attachment transfer id")
	}
	var id [16]byte
	copy(id[:], decoded)
	if isZero16(id) {
		return [16]byte{}, errors.New("invalid attachment transfer id")
	}
	return id, nil
}

func parseAttachmentUint(raw string) (uint64, error) {
	if raw == "" || (len(raw) > 1 && raw[0] == '0') {
		return 0, errors.New("invalid attachment integer")
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return 0, errors.New("invalid attachment integer")
	}
	return value, nil
}

func attachmentRouteTarget(route AttachmentRoute) ([]byte, error) {
	target := map[uint64]any{1: uint64(protocolVersion), 2: route.TransferID, 3: route.Operation}
	if route.Operation == PermitOperationUpload || route.Operation == PermitOperationDownload {
		target[4] = route.ChunkIndex
	}
	if route.Operation == PermitOperationSignal {
		target[5] = route.AttemptGeneration
	}
	return canonicalEncoding.Marshal(target)
}
