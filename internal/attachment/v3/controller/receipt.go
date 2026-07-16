package controller

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	attachmentv3 "github.com/rock3r/punaro/internal/attachment/v3"
	"github.com/zeebo/blake3"
)

// ApproveInboundOffer records an explicit local receipt decision for exactly
// one already-discovered offer. It never accepts, downloads, or decrypts an
// attachment; a fresh directory verification remains required afterwards.
// Repeating the same approval is safe and returns approved=false.
func (j *Journal) ApproveInboundOffer(punaroMessageID string, now time.Time) (approved bool, err error) {
	if j == nil || j.db == nil || strings.TrimSpace(punaroMessageID) == "" || now.UTC().Unix() < 0 {
		return false, errors.New("invalid v3 receipt approval")
	}
	var offer []byte
	err = j.db.QueryRowContext(context.Background(), `SELECT offer FROM controller_inbound_offers WHERE punaro_message_id = ?`, punaroMessageID).Scan(&offer)
	if errors.Is(err, sql.ErrNoRows) {
		return false, errors.New("unknown v3 receipt approval")
	}
	if err != nil || len(offer) == 0 {
		return false, errors.New("invalid stored v3 offer")
	}
	commitment := blake3.Sum256(offer)
	var previous []byte
	err = j.db.QueryRowContext(context.Background(), `SELECT offer_commitment FROM controller_receipt_approvals WHERE punaro_message_id = ?`, punaroMessageID).Scan(&previous)
	if err == nil {
		if !bytes.Equal(previous, commitment[:]) {
			return false, errors.New("changed v3 receipt approval")
		}
		return false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return false, err
	}
	_, err = j.db.ExecContext(context.Background(), `INSERT INTO controller_receipt_approvals(punaro_message_id, offer_commitment, approved_at) VALUES (?, ?, ?)`, punaroMessageID, commitment[:], now.UTC().Unix())
	if err != nil {
		return false, err
	}
	return true, nil
}

// PrepareApprovedReceipt returns a canonical discovered offer only after an
// explicit local approval and a new exact directory verification. It is the
// last discovery-stage boundary before a future recipient transfer worker may
// obtain permits or touch an output path.
func (j *Journal) PrepareApprovedReceipt(ctx context.Context, inbound InboundOffer, resolver TransferBindingResolver, directory attachmentv3.EnvelopeDirectoryKeyResolver, now time.Time) (attachmentv3.OfferNotice, error) {
	if j == nil || j.db == nil {
		return attachmentv3.OfferNotice{}, errors.New("controller journal is unavailable")
	}
	notice, _, err := j.RecordInboundOffer(inbound)
	if err != nil {
		return attachmentv3.OfferNotice{}, err
	}
	mapping, found, err := j.mapping(inbound.RelayConversationID)
	if err != nil || !found || VerifyFreshMapping(ctx, mapping, resolver, now) != nil {
		return attachmentv3.OfferNotice{}, errors.New("fresh v3 receipt directory binding is unavailable")
	}
	if _, _, err := attachmentv3.VerifyOfferNotice(notice, directory, now); err != nil {
		return attachmentv3.OfferNotice{}, errors.New("fresh v3 receipt offer verification is unavailable")
	}
	if !j.receiptApproved(inbound.PunaroMessageID, notice.Raw) {
		return attachmentv3.OfferNotice{}, errors.New("v3 receipt requires explicit approval")
	}
	return notice, nil
}

func (j *Journal) receiptApproved(punaroMessageID string, offer []byte) bool {
	if strings.TrimSpace(punaroMessageID) == "" || len(offer) == 0 {
		return false
	}
	commitment := blake3.Sum256(offer)
	var stored []byte
	err := j.db.QueryRowContext(context.Background(), `SELECT offer_commitment FROM controller_receipt_approvals WHERE punaro_message_id = ?`, punaroMessageID).Scan(&stored)
	return err == nil && bytes.Equal(stored, commitment[:])
}
