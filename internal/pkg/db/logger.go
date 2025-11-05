// Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/agntcy/identity/internal/pkg/log"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

const (
	nanosecsInMillisec = 1e6

	//nolint:lll // ignore the linter complaining about the length of this line
	traceStr = logger.Green + "%s\n\t" + logger.Reset + logger.Yellow + "[%.3fms] " + logger.BlueBold + "[rows:%v]" + logger.Reset + logger.Cyan + " %s" + logger.Reset
)

type logrusLogger struct{}

func NewLogrusLogger() logger.Interface {
	return &logrusLogger{}
}

func (l *logrusLogger) Error(ctx context.Context, msg string, data ...any) {
	log.FromContext(ctx).Errorf(msg, data...)
}

func (l *logrusLogger) Info(ctx context.Context, msg string, data ...any) {
	log.FromContext(ctx).Infof(msg, data...)
}

func (l *logrusLogger) Warn(ctx context.Context, msg string, data ...any) {
	log.FromContext(ctx).Infof(msg, data...)
}

func (l *logrusLogger) LogMode(logger.LogLevel) logger.Interface {
	// No need to implement this
	return l
}

func (l *logrusLogger) Trace(
	ctx context.Context,
	begin time.Time,
	fc func() (sql string, rowsAffected int64),
	err error,
) {
	elapsed := time.Since(begin)

	sql, rows := fc()
	rowsStr := fmt.Sprintf("%v", rows)

	if rows == -1 {
		rowsStr = "-"
	}

	logEntry := log.FromContext(ctx)

	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		logEntry = logEntry.WithError(err)
	}

	logEntry.Debugf(
		traceStr,
		utils.FileWithLineNum(),
		float64(elapsed.Nanoseconds())/nanosecsInMillisec,
		rowsStr,
		sql,
	)
}
