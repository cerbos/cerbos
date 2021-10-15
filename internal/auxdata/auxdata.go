// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/config"
)

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

func (ad *AuxData) Validate(ctx context.Context, adProto *requestv1.AuxData) (*enginev1.AuxData, error) {
	if adProto == nil {
		return nil, nil
	}

	jwtPB, err := ad.jwt.parseAndVerify(ctx, adProto.Jwt)
	if err != nil {
		return nil, err
	}

	return &enginev1.AuxData{Jwt: jwtPB}, nil
}
