// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package integrations

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/marketplacemetering"
	"github.com/aws/smithy-go/logging"
	"go.uber.org/zap"
)

var AWSProductCode = ""

func Init(ctx context.Context) error {
	if AWSProductCode != "" {
		return initAWSMarketplace(ctx)
	}

	return nil
}

func initAWSMarketplace(ctx context.Context) error {
	var awsPublicKeyVersion int32 = 1
	logger := zap.S().Named("aws")
	logger.Info("Configuring AWS marketplace integration")

	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		logger.Errorw("Failed to load AWS configuration", "error", err)
		return fmt.Errorf("failed to load AWS configuration: %w", err)
	}

	client := marketplacemetering.NewFromConfig(cfg, func(o *marketplacemetering.Options) {
		o.Logger = logging.LoggerFunc(func(classification logging.Classification, format string, v ...interface{}) {
			switch classification {
			case logging.Warn:
				logger.Warnf(format, v...)
			case logging.Debug:
				logger.Debugf(format, v...)
			default:
				logger.Infof(format, v...)
			}
		})
	})

	if _, err := client.RegisterUsage(ctx, &marketplacemetering.RegisterUsageInput{
		ProductCode:      &AWSProductCode,
		PublicKeyVersion: &awsPublicKeyVersion,
	}); err != nil {
		logger.Errorw("Failed to configure AWS marketplace integration", "error", err)
		return fmt.Errorf("failed to configure AWS marketplace integration: %w", err)
	}

	return nil
}
