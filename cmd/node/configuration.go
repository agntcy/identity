// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"time"
)

//nolint:lll // Ignore linting for long lines
type Configuration struct {
	ServerHttpHost                                          string        `split_words:"true" default:":4000"`
	ServerGrpcHost                                          string        `split_words:"true" default:":4001"`
	GoEnv                                                   string        `split_words:"true" default:"production"`
	LogLevel                                                string        `split_words:"true" default:"InfoLevel"`
	DbHost                                                  string        `split_words:"true"                                 required:"true"`
	DbPort                                                  string        `split_words:"true"                                 required:"true"`
	DbName                                                  string        `split_words:"true" default:"identity"`
	DbUsername                                              string        `split_words:"true"                                 required:"true"`
	DbPassword                                              string        `split_words:"true"                                 required:"true"`
	DbUseSsl                                                bool          `split_words:"true" default:"false"`
	ServerGrpcKeepAliveEnvorcementPolicyMinTime             int           `split_words:"true" default:"300"`
	ServerGrpcKeepAliveEnvorcementPolicyPermitWithoutStream bool          `split_words:"true" default:"false"`
	ServerGrpcKeepAliveServerParametersMaxConnectionIdle    int           `split_words:"true" default:"100"`
	ServerGrpcKeepAliveServerParametersTime                 int           `split_words:"true" default:"7200"`
	ServerGrpcKeepAliveServerParametersTimeout              int           `split_words:"true" default:"20"`
	ClientGrpcKeepAliveClientParametersTime                 int           `split_words:"true" default:"100"`
	ClientGrpcKeepAliveClientParametersTimeout              int           `split_words:"true" default:"20"`
	ClientGrpcKeepAliveClientParametersPermitWithoutStream  bool          `split_words:"true" default:"false"`
	HttpServerWriteTimeout                                  int           `split_words:"true" default:"100"`
	HttpServerIdleTimeout                                   int           `split_words:"true" default:"100"`
	HttpServerReadTimeout                                   int           `split_words:"true" default:"100"`
	HttpServerReadHeaderTimeout                             int           `split_words:"true" default:"100"`
	DefaultCallTimeout                                      time.Duration `split_words:"true" default:"10000ms"`
}

func (c *Configuration) IsDev() bool {
	return c.GoEnv == "development"
}

func (c *Configuration) IsProd() bool {
	return c.GoEnv == "production"
}
