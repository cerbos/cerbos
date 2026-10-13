// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"errors"
	"fmt"

	"github.com/sourcegraph/conc/pool"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/observability/tracing"
)

const maxExtractGoRoutines = 4

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

	if jwt := adProto.GetJwt(); jwt != nil {
		jwtPB, err := ad.jwt.extract(ctx, jwt)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToExtractJWT, err)
		}

		return &enginev1.AuxData{Jwt: jwtPB}, nil
	}

	jwts := adProto.GetJwts()
	numJWTs := len(jwts)
	switch numJWTs {
	case 0:
		return nil, nil
	case 1:
		for name, jwt := range jwts {
			claims, err := ad.jwt.extract(ctx, jwt)
			if err != nil {
				return nil, fmt.Errorf("%w: %w", ErrFailedToExtractJWT, err)
			}

			return &enginev1.AuxData{Jwts: map[string]*enginev1.AuxData_JWT{name: {Claims: claims}}}, nil
		}
		return nil, nil
	default:
		extractPool := pool.NewWithResults[namedJWT]().WithContext(ctx).WithMaxGoroutines(maxExtractGoRoutines).WithFailFast()
		for name, jwt := range jwts {
			extractPool.Go(func(ctx context.Context) (namedJWT, error) {
				claims, err := ad.jwt.extract(ctx, jwt)
				if err != nil {
					return namedJWT{}, fmt.Errorf("failed to extract JWT %q: %w", name, err)
				}

				return namedJWT{name: name, claims: &enginev1.AuxData_JWT{Claims: claims}}, nil
			})
		}

		extractions, err := extractPool.Wait()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToExtractJWT, err)
		}

		out := &enginev1.AuxData{Jwts: make(map[string]*enginev1.AuxData_JWT, numJWTs)}
		for _, ext := range extractions {
			out.Jwts[ext.name] = ext.claims
		}

		return out, nil
	}
}

type namedJWT struct {
	claims *enginev1.AuxData_JWT
	name   string
}
