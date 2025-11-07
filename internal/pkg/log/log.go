// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package log

import (
	"context"
	"maps"
	"os"

	"github.com/sirupsen/logrus"
)

type contextLogFieldsKey struct{}

func Init(isDev bool) {
	logrus.SetOutput(os.Stdout)

	var formatter logrus.Formatter

	if isDev {
		formatter = &logrus.TextFormatter{
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			DisableQuote:           true,
			ForceColors:            true,
		}
	} else {
		formatter = &logrus.JSONFormatter{}
	}

	logrus.SetFormatter(formatter)
}

// SetLogLevel : Configure log level
func SetLogLevel(aLogLevel string) {
	// Set log level
	logLevel := logrus.InfoLevel
	if aLogLevel == "DebugLevel" {
		logLevel = logrus.DebugLevel
	}

	logrus.SetLevel(logLevel)
}

// Info logs a message at level Info
func Info(args ...any) {
	logrus.Info(args...)
}

// Debug Info logs a message at level Debug
func Debug(args ...any) {
	logrus.Debug(args...)
}

// Fatal logs a message at level Fatal then the process will exit with status set to 1
func Fatal(args ...any) {
	logrus.Fatal(args...)
}

// Error logs a message at level Error
func Error(args ...any) {
	logrus.Error(args...)
}

// Warn logs a message at level Warn
func Warn(args ...any) {
	logrus.Warn(args...)
}

// WithError creates an entry from the standard logger and adds an error field to it
func WithError(err error) *logrus.Entry {
	return logrus.WithError(err)
}

func EnrichContext(ctx context.Context, fields logrus.Fields) context.Context {
	nCtx := ctx

	if stored, ok := ctx.Value(contextLogFieldsKey{}).(logrus.Fields); ok {
		maps.Copy(stored, fields)
	} else {
		nCtx = context.WithValue(ctx, contextLogFieldsKey{}, fields)
	}

	return nCtx
}

func FromContext(ctx context.Context) *logrus.Entry {
	fields, ok := ctx.Value(contextLogFieldsKey{}).(logrus.Fields)
	if !ok {
		return logrus.WithContext(ctx)
	}

	return logrus.WithContext(ctx).WithFields(fields)
}

func WithFields(fields logrus.Fields) *logrus.Entry {
	return logrus.WithFields(fields)
}
