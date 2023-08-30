// Copyright 2021-2023 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/lestrrat-go/httprc"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"go.uber.org/zap"
	"google.golang.org/protobuf/types/known/structpb"

	requestv1 "github.com/cerbos/cerbos/api/genpb/cerbos/request/v1"
	"github.com/cerbos/cerbos/internal/cache"
	"github.com/cerbos/cerbos/internal/observability/logging"
	"github.com/cerbos/cerbos/internal/observability/tracing"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	defaultCacheExpiry = 10 * time.Minute
	defaultCacheSize   = 256
)

var (
	cacheEntry          = struct{}{}
	errNilLocalKeySet   = errors.New("nil local keyset")
	errNoKeySetToVerify = errors.New("cannot determine keyset to use for validating the JWT")
)

type jwtHelper struct {
	keySets map[string]keySet
	cache   *cache.Cache[string, struct{}]
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

		var jwkCache *jwk.Cache
		for _, ks := range conf.KeySets {
			ks := ks
			switch {
			case ks.Remote != nil:
				if jwkCache == nil {
					log := logging.FromContext(ctx).Named("auxdata")
					errSink := func(err error) {
						log.Warn("Error refreshing keyset", zap.Error(err))
					}

					jwkCache = jwk.NewCache(ctx, jwk.WithErrSink(httprc.ErrSinkFunc(errSink)))
				}
				jh.keySets[ks.ID] = newRemoteKeySet(jwkCache, ks.Remote)
			case ks.Local != nil:
				jh.keySets[ks.ID] = newLocalKeySet(ks.Local)
			}
		}

		if conf.CacheSize > 0 {
			jh.cache = cache.New[string, struct{}]("jwt", uint(conf.CacheSize))
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

	cacheKey := ""
	if j.cache != nil {
		if lastIdx := strings.LastIndexByte(auxJWT.Token, '.'); lastIdx > 0 {
			// use the token signature as the cache key
			cacheKey = auxJWT.Token[lastIdx:]
		}
	}

	parseOpts, err := j.parseOptions(ctx, auxJWT, cacheKey)
	if err != nil {
		return nil, err
	}

	return j.doExtract(ctx, auxJWT, parseOpts, cacheKey)
}

func (j *jwtHelper) parseOptions(ctx context.Context, auxJWT *requestv1.AuxData_JWT, cacheKey string) ([]jwt.ParseOption, error) {
	if !j.verify {
		return []jwt.ParseOption{jwt.WithVerify(false), jwt.WithValidate(true)}, nil
	}

	// Check whether this token has already been verified
	if cacheKey != "" {
		if _, ok := j.cache.Get(cacheKey); ok {
			return []jwt.ParseOption{jwt.WithVerify(false), jwt.WithValidate(true)}, nil
		}
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

func (j *jwtHelper) doExtract(ctx context.Context, auxJWT *requestv1.AuxData_JWT, parseOpts []jwt.ParseOption, cacheKey string) (map[string]*structpb.Value, error) {
	token, err := jwt.ParseString(auxJWT.Token, parseOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to parse JWT: %w", err)
	}

	if cacheKey != "" {
		expiry := defaultCacheExpiry
		if exp := time.Until(token.Expiration()); exp > 0 {
			expiry = exp
		}

		j.cache.SetWithExpire(cacheKey, cacheEntry, expiry)
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
	*jwk.Cache
	url string
}

func newRemoteKeySet(cache *jwk.Cache, src *RemoteSource) *remoteKeySet {
	if src.RefreshInterval > 0 {
		_ = cache.Register(src.URL, jwk.WithRefreshInterval(src.RefreshInterval))
	} else {
		_ = cache.Register(src.URL)
	}

	return &remoteKeySet{Cache: cache, url: src.URL}
}

func (rks *remoteKeySet) keySet(ctx context.Context) (jwk.Set, error) {
	return rks.Get(ctx, rks.url)
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
