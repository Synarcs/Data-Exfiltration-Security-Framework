/*
	Copyright (c) 2024–2025 Synarcs. All rights reserved.
	SPDX-License-Identifier: AGPL-3.0
*/

package utils

import (
	"crypto/ecdsa"
	"crypto/x509"
	"time"
)

const (
	DEBUG = false
)

type ControlelrCertConfig struct {
	Cert     *x509.Certificate
	Key      *ecdsa.PrivateKey
	KeySize  int
	Duration time.Duration
}
