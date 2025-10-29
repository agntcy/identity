// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package httputil

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/agntcy/identity/pkg/log"
)

// Timeout : API timeout time
const Timeout = 30

// GetJSON : Get data
func GetJSON(ctx context.Context, uri string, result interface{}) error {
	return getJSON(ctx, uri, nil, result)
}

func GetWithRawBody(
	ctx context.Context,
	uri string,
	headers map[string]string,
	result *string,
) error {
	body, _, err := Get(ctx, uri, headers)
	if err != nil {
		log.Debug("Got error", err)
		return err
	}

	*result = string(body)

	return nil
}

func Get(ctx context.Context,
	uri string,
	headers map[string]string,
) ([]byte, http.Header, error) {
	// Create context
	ctx, cancel := context.WithTimeout(ctx, Timeout*time.Second)
	defer cancel()

	// Create a new request using http
	log.Debug("Getting uri ", uri)

	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, uri, http.NoBody)

	// Add headers
	log.Debug("Getting with headers ", headers)

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Send req using http Client
	client := &http.Client{}

	resp, err := client.Do(req)
	if err != nil {
		log.Debug("Got error", err)
		return nil, nil, err
	}

	defer resp.Body.Close()

	// Read and parse data
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Debug("Got error reading body", err)
		return nil, nil, err
	}

	log.Debug("Server response status code is ", resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("got status code %d", resp.StatusCode)
	}

	return body, resp.Header, nil
}

func getJSON(
	ctx context.Context,
	uri string,
	headers map[string]string,
	result interface{},
) error {
	body, _, err := Get(ctx, uri, headers)
	if err != nil {
		log.Debug("Got error", err)
		return err
	}

	jsonErr := json.Unmarshal(body, &result)
	if jsonErr != nil {
		log.Debug("Got error ", jsonErr)
		return err
	}

	return nil
}
