// Copyright 2025 Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"os"

	v1alphaclient "github.com/agntcy/identity/api/client/models"
	vctypes "github.com/agntcy/identity/internal/core/vc/types"
)

var errUnsupportedFileFormat = errors.New("unsupported badge file format")

var fileParsers = []func(data []byte) ([]*vctypes.EnvelopedCredential, error){
	parseAsVcWellKnownResponse,
	parseAsVcList,
	parseAsVc,
}

func readBadgesFromFile(path string) (iter.Seq2[*vctypes.EnvelopedCredential, error], error) {
	var vcs []*vctypes.EnvelopedCredential

	// Check if the badge file exists
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("file does not exist: %s", path)
	}

	// Read the badge file
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	for _, parser := range fileParsers {
		vcs, err = parser(data)
		if err != nil {
			if errors.Is(err, errUnsupportedFileFormat) {
				continue
			}

			return nil, fmt.Errorf("error unmarshalling badge data: %w", err)
		} else {
			break
		}
	}

	if err != nil {
		return nil, fmt.Errorf("error unmarshalling badge data: %w", err)
	}

	if len(vcs) == 0 {
		return nil, fmt.Errorf("no verifiable credentials found in the file: %s", path)
	}

	return func(yield func(*vctypes.EnvelopedCredential, error) bool) {
		for _, vc := range vcs {
			if vc.EnvelopeType != vctypes.CREDENTIAL_ENVELOPE_TYPE_JOSE {
				if !yield(nil, fmt.Errorf("skipping unsupported envelope type: %s", vc.EnvelopeType)) {
					return
				}

				continue
			}

			if !yield(vc, nil) {
				return
			}
		}
	}, nil
}

func parseAsVcWellKnownResponse(data []byte) ([]*vctypes.EnvelopedCredential, error) {
	result := []*vctypes.EnvelopedCredential{}

	var vcs v1alphaclient.V1alpha1GetVcWellKnownResponse

	err := json.Unmarshal(data, &vcs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsupportedFileFormat, err)
	}

	for _, vc := range vcs.Vcs {
		var envelopedCredential vctypes.EnvelopedCredential

		envelopedCredential.Value = vc.Value

		err := envelopedCredential.EnvelopeType.UnmarshalText([]byte(*vc.EnvelopeType))
		if err != nil {
			return nil, err
		}

		result = append(result, &envelopedCredential)
	}

	return result, nil
}

func parseAsVcList(data []byte) ([]*vctypes.EnvelopedCredential, error) {
	var vcs []*vctypes.EnvelopedCredential

	err := json.Unmarshal(data, &vcs)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsupportedFileFormat, err)
	}

	return vcs, nil
}

func parseAsVc(data []byte) ([]*vctypes.EnvelopedCredential, error) {
	var vc vctypes.EnvelopedCredential

	err := json.Unmarshal(data, &vc)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errUnsupportedFileFormat, err)
	}

	return []*vctypes.EnvelopedCredential{&vc}, nil
}
