// Copyright 2026 Secria, Inc.
// SPDX-License-Identifier: AGPL-3.0-only

import { copyFileSync, rmSync } from 'node:fs'

rmSync('dist', { recursive: true, force: true })
for (const file of ['LICENSE', 'NOTICE']) copyFileSync(`../${file}`, file)
