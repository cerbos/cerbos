// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package git

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/go-git/go-git/v5/plumbing/transport/http"
	"github.com/go-git/go-git/v5/plumbing/transport/ssh"
	"go.uber.org/multierr"

	"github.com/cerbos/cerbos/internal/storage"
	"github.com/cerbos/cerbos/internal/util"
)

const (
	confKey                 = storage.ConfKey + ".git"
	defaultOperationTimeout = 60 * time.Second
)

// Conf holds the configuration for Git storage driver.
type Conf struct {
	// Protocol is the Git protocol to use. Valid values are https, ssh, and file.
	Protocol string `yaml:"protocol"`
	// URL is the URL to the Git repo.
	URL string `yaml:"url"`
	// Branch is the branch to checkout.
	Branch string `yaml:"branch"`
	// SubDir is the path under the checked-out Git repo where the policies are stored.
	SubDir string `yaml:"subDir,omitempty"`
	// CheckoutDir is the local path to checkout the Git repo to.
	CheckoutDir string `yaml:"checkoutDir"`
	// [DEPRECATED] ScratchDir is the directory to use for holding temporary data.
	ScratchDir string `yaml:"scratchDir"`
	// SSH holds auth details for the SSH protocol.
	SSH *SSHAuth `yaml:"ssh,omitempty"`
	// HTTPS holds auth details for the HTTPS protocol.
	HTTPS *HTTPSAuth `yaml:"https,omitempty"`
	// OperationTimeout specifies the timeout for git operations.
	OperationTimeout *time.Duration `yaml:"operationTimeout,omitempty"`
	// UpdatePollInterval specifies the interval to poll the Git repository for changes. Set to 0 to disable.
	UpdatePollInterval time.Duration `yaml:"updatePollInterval"`
}

// SSHAuth holds auth details for the SSH protocol.
type SSHAuth struct {
	// User is the git user. Defaults to git.
	User string `yaml:"user"`
	// PrivateKeyFile is the path to the SSH private key file.
	PrivateKeyFile string `yaml:"privateKeyFile"`
	// Password is the password to the SSH private key.
	Password string `yaml:"password"`
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
	// Username is the username to use for authentication.
	Username string `yaml:"username"`
	// Password is the password (or token) to use for authentication.
	Password string `yaml:"password"`
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

func (conf *Conf) Validate() error {
	var errs []error

	switch conf.Protocol {
	case "ssh", "http", "https", "file":
	default:
		errs = append(errs, fmt.Errorf("unknown git protocol: %s", conf.Protocol))
	}

	if conf.URL == "" {
		errs = append(errs, errors.New("git URL is required"))
	}

	if conf.CheckoutDir == "" {
		cacheDir, err := os.UserCacheDir()
		if err != nil {
			errs = append(errs, fmt.Errorf("checkoutDir unspecified and failed to determine user cache dir: %w", err))
		} else {
			conf.CheckoutDir = filepath.Join(cacheDir, util.AppName, "git")
		}
	}

	if len(errs) > 0 {
		return multierr.Combine(errs...)
	}

	return nil
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
