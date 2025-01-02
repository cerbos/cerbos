// Copyright 2021-2025 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"

	"google.golang.org/protobuf/proto"

	enginev1 "github.com/cerbos/cerbos/api/genpb/cerbos/engine/v1"
	policyv1 "github.com/cerbos/cerbos/api/genpb/cerbos/policy/v1"
	"github.com/cerbos/cerbos/internal/jsonschema"
	"github.com/cerbos/cerbos/internal/util"
	"github.com/cerbos/cerbos/internal/validator"
)

type Principals struct {
	LoadError error
	Fixtures  map[string]*enginev1.Principal
	Groups    map[string][]string
	FilePath  string
}

type Resources struct {
	LoadError error
	Fixtures  map[string]*enginev1.Resource
	Groups    map[string][]string
	FilePath  string
}

type AuxData struct {
	LoadError error
	Fixtures  map[string]*enginev1.AuxData
	FilePath  string
}

type TestFixture struct {
	Principals *Principals
	Resources  *Resources
	AuxData    *AuxData
}

const (
	principalsFileName = "principals"
	resourcesFileName  = "resources"
)

var auxDataFileNames = []string{"auxdata", "auxData", "aux_data"}

func LoadTestFixture(fsys fs.FS, path string, continueOnError bool) (tf *TestFixture, err error) {
	tf = new(TestFixture)
	tf.Principals, err = loadPrincipals(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	tf.Resources, err = loadResources(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	tf.AuxData, err = loadAuxData(fsys, path)
	if err != nil && !continueOnError {
		return nil, err
	}

	return tf, nil
}

func loadResources(fsys fs.FS, path string) (*Resources, error) {
	fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, resourcesFileName))
	if err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	resources := &Resources{
		FilePath: fp,
	}

	pb := &policyv1.TestFixture_Resources{}
	if err := loadFixtureElement(fsys, fp, pb, jsonschema.ValidateResourceFixtures); err != nil {
		resources.LoadError = err
		return resources, fmt.Errorf("failed to load resources: %w", err)
	}

	resources.Fixtures = pb.Resources

	resources.Groups, err = checkGroupDefinitions(pb.ResourceGroups, resourceGroupMembers, existsInMap(pb.Resources))
	if err != nil {
		resources.LoadError = err
		return nil, fmt.Errorf("failed to load resources: %w", err)
	}

	return resources, nil
}

func loadPrincipals(fsys fs.FS, path string) (*Principals, error) {
	fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, principalsFileName))
	if err != nil {
		if errors.Is(err, util.ErrNoMatchingFiles) {
			return nil, nil
		}
		return nil, err
	}

	principals := &Principals{
		FilePath: fp,
	}

	pb := &policyv1.TestFixture_Principals{}
	if err := loadFixtureElement(fsys, fp, pb, jsonschema.ValidatePrincipalFixtures); err != nil {
		principals.LoadError = err
		return principals, fmt.Errorf("failed to load principals: %w", err)
	}

	principals.Fixtures = pb.Principals

	principals.Groups, err = checkGroupDefinitions(pb.PrincipalGroups, principalGroupMembers, existsInMap(pb.Principals))
	if err != nil {
		principals.LoadError = err
		return nil, fmt.Errorf("failed to load principals: %w", err)
	}

	return principals, nil
}

func loadAuxData(fsys fs.FS, path string) (*AuxData, error) {
	for _, fn := range auxDataFileNames {
		fp, err := util.GetOneOfSupportedFileNames(fsys, filepath.Join(path, fn))
		if err != nil {
			if errors.Is(err, util.ErrNoMatchingFiles) {
				continue
			}
			return nil, err
		}

		auxData := &AuxData{
			FilePath: fp,
		}

		pb := &policyv1.TestFixture_AuxData{}
		if err := loadFixtureElement(fsys, fp, pb, jsonschema.ValidateAuxDataFixtures); err != nil {
			auxData.LoadError = err
			return auxData, fmt.Errorf("failed to load aux data: %w", err)
		}

		auxData.Fixtures = pb.AuxData
		return auxData, nil
	}

	return nil, nil
}

func loadFixtureElement(fsys fs.FS, path string, pb proto.Message, validate func(fs.FS, string) error) error {
	err := validate(fsys, path)
	if err != nil {
		return err
	}

	err = util.LoadFromJSONOrYAML(fsys, path, pb)
	if err != nil {
		return err
	}

	return validator.Validate(pb)
}

func (tf *TestFixture) lookupPrincipal(name string) (*enginev1.Principal, bool) {
	if tf == nil || tf.Principals == nil {
		return nil, false
	}

	principal, ok := tf.Principals.Fixtures[name]
	return principal, ok
}

func (tf *TestFixture) lookupPrincipalGroup(name string) ([]string, bool) {
	if tf == nil || tf.Principals == nil {
		return nil, false
	}

	group, ok := tf.Principals.Groups[name]
	return group, ok
}

func (tf *TestFixture) lookupResource(name string) (*enginev1.Resource, bool) {
	if tf == nil || tf.Resources == nil {
		return nil, false
	}

	resource, ok := tf.Resources.Fixtures[name]
	return resource, ok
}

func (tf *TestFixture) lookupResourceGroup(name string) ([]string, bool) {
	if tf == nil || tf.Resources == nil {
		return nil, false
	}

	group, ok := tf.Resources.Groups[name]
	return group, ok
}

func (tf *TestFixture) lookupAuxData(name string) (*enginev1.AuxData, bool) {
	if tf == nil || tf.AuxData == nil {
		return nil, false
	}

	auxData, ok := tf.AuxData.Fixtures[name]
	return auxData, ok
}
