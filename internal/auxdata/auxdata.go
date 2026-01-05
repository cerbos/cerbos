// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"errors"
	"fmt"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

var ErrFailedToExtractJWT = errors.New("failed to extract JWT")

type AuxData struct {
	jwt *jwtHelper
}

func New(ctx context.Context) (*AuxData, error) {
	conf := &Conf{}
	if err := config.GetSection(conf); err != nil {
		return nil, err
	}

	return NewFromConf(ctx, conf), nil
}

func NewFromConf(ctx context.Context, conf *Conf) *AuxData {
	return &AuxData{jwt: newJWTHelper(ctx, conf.JWT)}
}

func NewWithoutVerification(ctx context.Context) *AuxData {
	return &AuxData{jwt: newJWTHelper(ctx, &JWTConf{DisableVerification: true})}
}

// Extract auxiliary data and convert to format expected by the engine.
func (ad *AuxData) Extract(ctx context.Context, adProto *requestv1.AuxData) (*enginev1.AuxData, error) {
	if adProto == nil {
		return nil, nil
	}

	ctx, span := tracing.StartSpan(ctx, "aux_data.Extract")
	defer span.End()

	jwtPB, err := ad.jwt.extract(ctx, adProto.Jwt)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFailedToExtractJWT, err)
	}

	return &enginev1.AuxData{Jwt: jwtPB}, nil
}
