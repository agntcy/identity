#!/bin/sh
# Copyright 2025 AGNTCY Contributors (https://github.com/agntcy)
# SPDX-License-Identifier: Apache-2.0

docker run --rm -v "$PWD/..:/identity" -w /identity vektra/mockery:3
