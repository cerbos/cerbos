// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/config"
	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	confKey                 = storage.ConfKey + ".git"
	defaultOperationTimeout = 60 * time.Second
)

// Conf is required (if driver is set to 'git') configuration for Git storage driver.
// +desc=This section is required only if storage.driver is git.
type Conf struct {
	// SSH holds auth details for the SSH protocol.
	SSH *SSHAuth `yaml:"ssh,omitempty"`
	// HTTPS holds auth details for the HTTPS protocol.
	HTTPS *HTTPSAuth `yaml:"https,omitempty"`
	// OperationTimeout specifies the timeout for git operations.
	OperationTimeout *time.Duration `yaml:"operationTimeout,omitempty" conf:",example=60s"`
	// Protocol is the Git protocol to use. Valid values are https, ssh, and file.
	Protocol string `yaml:"protocol" conf:"required,example=file"`
	// URL is the URL to the Git repo.
	URL string `yaml:"url" conf:"required,example=file://${HOME}/tmp/cerbos/policies"`
	// Branch is the branch to checkout.
	Branch string `yaml:"branch" conf:",example=policies"`
	// SubDir is the path under the checked-out Git repo where the policies are stored.
	SubDir string `yaml:"subDir,omitempty" conf:",example=policies"`
	// CheckoutDir is the local path to checkout the Git repo to.
	CheckoutDir string `yaml:"checkoutDir" conf:",example=${HOME}/tmp/cerbos/work"`
	// [DEPRECATED] ScratchDir is the directory to use for holding temporary data.
	ScratchDir string `yaml:"scratchDir" conf:",ignore"`
	// UpdatePollInterval specifies the interval to poll the Git repository for changes. Set to 0 to disable.
	UpdatePollInterval time.Duration `yaml:"updatePollInterval" conf:",example=60s"`
}

// SSHAuth holds auth details for the SSH protocol.
type SSHAuth struct {
	// The git user. Defaults to git.
	User string `yaml:"user" conf:",example=git"`
	// The path to the SSH private key file.
	PrivateKeyFile string `yaml:"privateKeyFile" conf:",example=${HOME}/.ssh/id_rsa"`
	// The password to the SSH private key.
	Password string `yaml:"password" conf:",example=pw"`
}

func (sa *SSHAuth) Auth() (transport.AuthMethod, error) {
	if sa == nil || sa.PrivateKeyFile == "" {
		return nil, nil
	}

	user := "git"
	if sa.User != "" {
		user = sa.User
	}

	return ssh.NewPublicKeysFromFile(user, sa.PrivateKeyFile, sa.Password)
}

// HTTPSAuth holds auth details for the HTTPS protocol.
type HTTPSAuth struct {
	// The username to use for authentication.
	Username string `yaml:"username" conf:",example=cerbos"`
	// The password (or token) to use for authentication.
	Password string `yaml:"password" conf:",example=${GITHUB_TOKEN}"`
}

func (ha *HTTPSAuth) Auth() (transport.AuthMethod, error) {
	if ha == nil || (ha.Username == "" && ha.Password == "") {
		return nil, nil
	}

	return &http.BasicAuth{Username: ha.Username, Password: ha.Password}, nil
}

func (conf *Conf) Key() string {
	return confKey
}

func (conf *Conf) Validate() (errs error) {
	if conf.URL == "" {
		errs = multierr.Append(errs, errors.New("git URL is required"))
	}

	switch conf.Protocol {
	case "ssh":
	case "http", "https", "file":
		gitURL, err := url.Parse(conf.URL)
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("invalid git URL: %w", err))
		} else if gitURL.Scheme != conf.Protocol {
			if gitURL.Scheme == "" {
				gitURL.Scheme = conf.Protocol
				conf.URL = gitURL.String()
			} else {
				errs = multierr.Append(errs, fmt.Errorf("the URL scheme of storage.git.url (%s) should match the storage.git.protocol value (%s)", gitURL.Scheme, conf.Protocol))
			}
		}

	default:
		errs = multierr.Append(errs, fmt.Errorf("unknown git protocol: %s", conf.Protocol))
	}

	if conf.CheckoutDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			errs = multierr.Append(errs, fmt.Errorf("checkoutDir unspecified and failed to determine user cache dir: %w", err))
		} else {
			conf.CheckoutDir = filepath.Join(cacheDir, util.AppName, "git")
		}
	}

	subDir := conf.getSubDir()
	if filepath.IsAbs(subDir) || strings.HasPrefix(subDir, "../") || subDir == ".." {
		errs = multierr.Append(errs, errors.New("subDir must be a relative path within the repository"))
	}

	return errs
}

func (conf *Conf) getSubDir() string {
	return filepath.ToSlash(filepath.Clean(conf.SubDir))
}

func (conf *Conf) getBranch() string {
	branch := "master"
	if conf.Branch != "" {
		branch = conf.Branch
	}

	return branch
}

func (conf *Conf) getAuth() (transport.AuthMethod, error) {
	switch conf.Protocol {
	case "https":
		return conf.HTTPS.Auth()
	case "ssh":
		return conf.SSH.Auth()
	default:
		return nil, nil
	}
}

func (conf *Conf) getOpCtx(parent context.Context) (context.Context, context.CancelFunc) {
	if conf.OperationTimeout == nil {
		return context.WithTimeout(parent, defaultOperationTimeout)
	}

	return context.WithTimeout(parent, *conf.OperationTimeout)
}

func GetConf() (*Conf, error) {
	conf := &Conf{}
	err := config.GetSection(conf)

	return conf, err
}
