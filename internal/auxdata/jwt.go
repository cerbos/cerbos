// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/lestrrat-go/jwx/jwk"
	"github.com/lestrrat-go/jwx/jwt"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/util"
)

var (
	errNilLocalKeySet   = errors.New("nil local keyset")
	errNoKeySetToVerify = errors.New("cannot determine keyset to use for validating the JWT")
)

type jwtHelper struct {
	keySets map[string]keySet
	verify  bool
}

func newJWTHelper(ctx context.Context, conf *JWTConf) *jwtHelper {
	jh := &jwtHelper{verify: true}

	if conf == nil {
		return jh
	}

	jh.verify = !conf.DisableVerification

	if jh.verify {
		jh.keySets = make(map[string]keySet, len(conf.KeySets))

		var autoRefresh *jwk.AutoRefresh
		for _, ks := range conf.KeySets {
			ks := ks
			switch {
			case ks.Remote != nil:
				if autoRefresh == nil {
					autoRefresh = jwk.NewAutoRefresh(ctx)
				}
				jh.keySets[ks.ID] = newRemoteKeySet(autoRefresh, ks.Remote)
			case ks.Local != nil:
				jh.keySets[ks.ID] = newLocalKeySet(ks.Local)
			}
		}

		if autoRefresh != nil {
			errChan := make(chan jwk.AutoRefreshError, 1)
			autoRefresh.ErrorSink(errChan)
			go func() {
				log := logging.FromContext(ctx).Named("auxdata")
				for {
					select {
					case <-ctx.Done():
						return
					case err := <-errChan:
						log.Warn("Error refreshing keyset", zap.String("url", err.URL), zap.Error(err.Error))
					}
				}
			}()
		}
	}

	return jh
}

func (j *jwtHelper) extract(ctx context.Context, auxJWT *requestv1.AuxData_JWT) (map[string]*structpb.Value, error) {
	if auxJWT == nil || auxJWT.Token == "" {
		return nil, nil
	}

	ctx, span := tracing.StartSpan(ctx, "aux_data.ExtractJWT")
	defer span.End()

	parseOpts, err := j.parseOptions(ctx, auxJWT)
	if err != nil {
		return nil, err
	}

	return j.doExtract(ctx, auxJWT, parseOpts)
}

func (j *jwtHelper) parseOptions(ctx context.Context, auxJWT *requestv1.AuxData_JWT) ([]jwt.ParseOption, error) {
	if !j.verify {
		return nil, nil
	}

	var ks keySet

	// if keyset ID is not provided and we only have one keyset configured, use that as the default.
	if auxJWT.KeySetId == "" {
		if len(j.keySets) != 1 {
			return nil, errNoKeySetToVerify
		}

		for _, ksDef := range j.keySets {
			ks = ksDef
		}
	} else { // use the keyset specified in the request
		ksDef, ok := j.keySets[auxJWT.KeySetId]
		if !ok {
			return nil, fmt.Errorf("keyset not found: %s", auxJWT.KeySetId)
		}
		ks = ksDef
	}

	jwks, err := ks.keySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve keyset: %w", err)
	}

	return []jwt.ParseOption{jwt.WithKeySet(jwks), jwt.WithValidate(true)}, nil
}

func (j *jwtHelper) doExtract(ctx context.Context, auxJWT *requestv1.AuxData_JWT, parseOpts []jwt.ParseOption) (map[string]*structpb.Value, error) {
	token, err := jwt.ParseString(auxJWT.Token, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	jwtPBMap := make(map[string]*structpb.Value)
	for iter := token.Iterate(ctx); iter.Next(ctx); {
		p := iter.Pair()
		key, ok := p.Key.(string)
		if !ok {
			logging.FromContext(ctx).Named("auxdata").
				Warn("Ignoring JWT key-value pair because the key is not a string", zap.Any("pair", p), zap.Error(err))
		}

		value, err := util.ToStructPB(p.Value)
		if err != nil {
			logging.FromContext(ctx).Named("auxdata").
				Warn("Ignoring JWT key-value pair because the value is not in a known format", zap.Any("pair", p), zap.Error(err))
			continue
		}

		jwtPBMap[key] = value
	}

	return jwtPBMap, nil
}

type keySet interface {
	keySet(context.Context) (jwk.Set, error)
}

// remoteKeySet holds an auto-refreshing remote keyset.
type remoteKeySet struct {
	*jwk.AutoRefresh
	url string
}

func newRemoteKeySet(ar *jwk.AutoRefresh, src *RemoteSource) *remoteKeySet {
	if src.RefreshInterval > 0 {
		ar.Configure(src.URL, jwk.WithRefreshInterval(src.RefreshInterval))
	} else {
		ar.Configure(src.URL)
	}

	return &remoteKeySet{AutoRefresh: ar, url: src.URL}
}

func (rks *remoteKeySet) keySet(ctx context.Context) (jwk.Set, error) {
	return rks.AutoRefresh.Fetch(ctx, rks.url)
}

// localKeySet represents a keyset defined manually through the configuration.
type localKeySet func(context.Context) (jwk.Set, error)

func newLocalKeySet(src *LocalSource) localKeySet {
	if src.Data != "" {
		kbytes, err := base64.StdEncoding.DecodeString(src.Data)
		if err != nil {
			return func(context.Context) (jwk.Set, error) {
				return nil, fmt.Errorf("failed to apply base64 decoder to key data: %w", err)
			}
		}

		ks, err := jwk.Parse(kbytes, jwk.WithPEM(src.PEM))
		if err != nil {
			return func(context.Context) (jwk.Set, error) {
				return nil, fmt.Errorf("failed to parse key data: %w", err)
			}
		}

		return func(context.Context) (jwk.Set, error) { return ks, nil }
	}

	ks, err := jwk.ReadFile(src.File, jwk.WithPEM(src.PEM))
	if err != nil {
		return func(context.Context) (jwk.Set, error) {
			return nil, fmt.Errorf("failed to read keyset from '%s': %w", src.File, err)
		}
	}

	return func(context.Context) (jwk.Set, error) { return ks, nil }
}

func (lks localKeySet) keySet(ctx context.Context) (jwk.Set, error) {
	if lks == nil {
		return nil, errNilLocalKeySet
	}

	return lks(ctx)
}
