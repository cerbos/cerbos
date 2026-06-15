// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auxdata

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"
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
	keySets        map[string]keySet
	verify         bool
	acceptableSkew time.Duration
}

func newJWTHelper(ctx context.Context, conf *JWTConf) *jwtHelper {
	jh := &jwtHelper{verify: true}

	if conf == nil {
		return jh
	}

	jh.verify = !conf.DisableVerification
	jh.acceptableSkew = conf.AcceptableTimeSkew

	if jh.verify {
		log := logging.FromContext(ctx).Named("auxdata")
		jh.keySets = make(map[string]keySet, len(conf.KeySets))

		var jwkCache *jwk.Cache
		for _, ks := range conf.KeySets {
			var opts []any
			if ks.Insecure.OptionalAlg {
				log.Warn("[INSECURE CONFIG] Enabling optional alg field for key set", zap.String("keySetID", ks.ID))
				opts = append(opts, jws.WithInferAlgorithmFromKey(true))
			}

			if ks.Insecure.OptionalKid {
				log.Warn("[INSECURE CONFIG] Enabling optional kid field for key set", zap.String("keySetID", ks.ID))
				opts = append(opts, jws.WithRequireKid(false))
			}

			switch {
			case ks.Remote != nil:
				if jwkCache == nil {
					jwkCache = newJWKCache(ctx, log)
				}
				jh.keySets[ks.ID] = newRemoteKeySet(ctx, jwkCache, ks.Remote, ks.Insecure, opts)
			case ks.Local != nil:
				jh.keySets[ks.ID] = newLocalKeySet(ks.Local, ks.Insecure, opts)
			}
		}
	}

	return jh
}

func newJWKCache(ctx context.Context, log *zap.Logger) *jwk.Cache {
	jwkCache, err := jwk.NewCache(ctx, httprc.NewClient(httprc.WithErrorSink(jwkErrSink{log: log})))
	if err != nil {
		// this should never happen; jwk.NewCache only returns an error if you pass it an httprc.Client that has already been started.
		panic(fmt.Errorf("failed to create JWK cache: %w", err))
	}
	return jwkCache
}

type jwkErrSink struct {
	log *zap.Logger
}

func (j jwkErrSink) Put(_ context.Context, err error) {
	j.log.Warn("Error refreshing keyset", zap.Error(err))
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

func (j *jwtHelper) parseOptions(ctx context.Context, auxJWT *requestv1.AuxData_JWT) (opts []jwt.ParseOption, _ error) {
	if j.acceptableSkew > 0 {
		opts = []jwt.ParseOption{jwt.WithAcceptableSkew(j.acceptableSkew)}
	}

	if !j.verify {
		return append(opts, jwt.WithVerify(false), jwt.WithValidate(true)), nil
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

	jwks, jwksOpts, err := ks.keySet(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve keyset: %w", err)
	}

	return append(opts, jwt.WithKeySet(jwks, jwksOpts...), jwt.WithValidate(true)), nil
}

func (j *jwtHelper) doExtract(ctx context.Context, auxJWT *requestv1.AuxData_JWT, parseOpts []jwt.ParseOption) (map[string]*structpb.Value, error) {
	token, err := jwt.ParseString(auxJWT.Token, parseOpts...)
	if err != nil {
		return nil, newJWTExtractionError(err)
	}

	jwtPBMap := make(map[string]*structpb.Value)
	for _, key := range token.Keys() {
		var v any
		err := token.Get(key, &v)
		if err != nil {
			logging.FromContext(ctx).Named("auxdata").
				Warn("Ignoring JWT key-value pair because the value could not be read", zap.String("key", key), zap.Error(err))
			continue
		}

		value, err := util.ToStructPB(v)
		if err != nil {
			logging.FromContext(ctx).Named("auxdata").
				Warn("Ignoring JWT key-value pair because the value is not in a known format", zap.String("key", key), zap.Any("value", v), zap.Error(err))
			continue
		}

		jwtPBMap[key] = value
	}

	return jwtPBMap, nil
}

func newJWTExtractionError(err error) error {
	switch {
	case errors.Is(err, jwt.InvalidAudienceError()):
		return JWTExtractionError{
			Cause:       err,
			Description: "invalid audience (aud)",
		}
	case errors.Is(err, jwt.InvalidIssuedAtError()):
		return JWTExtractionError{
			Cause:       err,
			Description: "issued at time is in the future (iat)",
		}
	case errors.Is(err, jwt.InvalidIssuerError()):
		return JWTExtractionError{
			Cause:       err,
			Description: "invalid issuer (iss)",
		}
	case errors.Is(err, jwt.TokenExpiredError()):
		return JWTExtractionError{
			Cause:       err,
			Description: "token has expired (exp)",
		}
	case errors.Is(err, jwt.TokenNotYetValidError()):
		return JWTExtractionError{
			Cause:       err,
			Description: "token is not valid yet (nbf)",
		}
	default:
		return JWTExtractionError{
			Cause:       err,
			Description: "failed to parse JWT",
		}
	}
}

type JWTExtractionError struct {
	Cause       error
	Description string
}

func (ee JWTExtractionError) Error() string {
	if ee.Description != "" {
		return ee.Description
	}
	return ee.Cause.Error()
}

func (ee JWTExtractionError) Unwrap() error {
	return ee.Cause
}

type keySet interface {
	keySet(context.Context) (jwk.Set, []any, error)
}

// remoteKeySet holds an auto-refreshing remote keyset.
type remoteKeySet struct {
	*jwk.Cache
	url      string
	options  []any
	insecure InsecureKeySetOpt
}

func newRemoteKeySet(ctx context.Context, cache *jwk.Cache, src *RemoteSource, insecure InsecureKeySetOpt, options []any) *remoteKeySet {
	if src.RefreshInterval > 0 {
		_ = cache.Register(ctx, src.URL, jwk.WithConstantInterval(src.RefreshInterval))
	} else {
		_ = cache.Register(ctx, src.URL)
	}

	return &remoteKeySet{
		Cache:    cache,
		insecure: insecure,
		url:      src.URL,
		options:  options,
	}
}

func (rks *remoteKeySet) keySet(ctx context.Context) (jwk.Set, []any, error) {
	ks, err := rks.Lookup(ctx, rks.url)
	if err != nil {
		return nil, nil, err
	}

	if err := validateKeySet(ks, rks.insecure); err != nil {
		return nil, nil, err
	}

	return ks, rks.options, err
}

// localKeySet represents a keyset defined manually through the configuration.
type localKeySet func(context.Context) (jwk.Set, []any, error)

func newLocalKeySet(src *LocalSource, insecure InsecureKeySetOpt, options []any) localKeySet {
	var keyBytes []byte
	var err error
	switch {
	case src.File != "":
		f, err := os.Open(src.File)
		if err != nil {
			return func(context.Context) (jwk.Set, []any, error) {
				return nil, nil, fmt.Errorf("failed to open keyset file %s: %w", src.File, err)
			}
		}
		defer f.Close()

		keyBytes, err = io.ReadAll(f)
		if err != nil {
			return func(context.Context) (jwk.Set, []any, error) {
				return nil, nil, fmt.Errorf("failed to read from keyset file %s: %w", src.File, err)
			}
		}
	case src.Data != "":
		keyBytes, err = base64.StdEncoding.DecodeString(src.Data)
		if err != nil {
			return func(context.Context) (jwk.Set, []any, error) {
				return nil, nil, fmt.Errorf("failed to decode base64 encoded keyset data: %w", err)
			}
		}
	default:
		return func(context.Context) (jwk.Set, []any, error) {
			return nil, nil, fmt.Errorf("one of auxData.jwt.keySets[].local.data or auxData.jwt.keySets[].local.file must be specified")
		}
	}

	ks, err := jwk.Parse(keyBytes, jwk.WithPEM(src.PEM))
	if err != nil {
		if errors.Is(err, jwa.ErrInvalidKeyAlgorithm()) {
			return func(context.Context) (jwk.Set, []any, error) {
				return nil, nil, fmt.Errorf("invalid algorithm (alg)")
			}
		}

		return func(context.Context) (jwk.Set, []any, error) {
			return nil, nil, fmt.Errorf("failed to parse key data: %w", err)
		}
	}

	if !src.PEM {
		if err := validateKeySet(ks, insecure); err != nil {
			return func(context.Context) (jwk.Set, []any, error) {
				return nil, nil, err
			}
		}
	}

	return func(context.Context) (jwk.Set, []any, error) {
		return ks, options, nil
	}
}

func (lks localKeySet) keySet(ctx context.Context) (jwk.Set, []any, error) {
	if lks == nil {
		return nil, nil, errNilLocalKeySet
	}

	return lks(ctx)
}

func validateKeySet(keySet jwk.Set, insecure InsecureKeySetOpt) error {
	if insecure.OptionalAlg && insecure.OptionalKid {
		return nil
	}

	for idx := range keySet.Len() {
		key, ok := keySet.Key(idx)
		if !ok {
			return fmt.Errorf("failed to get key at idx %d", idx)
		}

		if err := validateKey(key, insecure.OptionalAlg, insecure.OptionalKid); err != nil {
			return fmt.Errorf("failed to validate key at idx %d: %w", idx, err)
		}
	}

	return nil
}

func validateKey(key jwk.Key, optionalAlg, optionalKid bool) error {
	if alg, ok := key.Algorithm(); !optionalAlg {
		if !ok {
			return fmt.Errorf("missing algorithm (alg)")
		}

		if alg.String() == "" {
			return fmt.Errorf("empty algorithm (alg)")
		}
	}

	if kid, ok := key.KeyID(); !optionalKid {
		if !ok {
			return fmt.Errorf("missing key ID (kid)")
		}

		if kid == "" {
			return fmt.Errorf("empty key ID (kid)")
		}
	}

	return nil
}
