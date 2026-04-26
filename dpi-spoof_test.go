/*

Warpnet - Decentralized Social Network
Copyright (C) 2025 Vadim Filin, https://github.com/Warp-net,
<github.com.mecdy@passmail.net>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.

WarpNet is provided "as is" without warranty of any kind, either expressed or implied.
Use at your own risk. The maintainers shall not be liable for any damages or data loss
resulting from the use or misuse of this software.
*/

// Copyright 2025 Vadim Filin
// SPDX-License-Identifier: AGPL-3.0-or-later

package camouflage

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestRandDuration_Zero(t *testing.T) {
	d := randDuration(0)
	assert.Equal(t, time.Duration(0), d)
}

func TestRandDuration_Negative(t *testing.T) {
	d := randDuration(-time.Second)
	assert.Equal(t, time.Duration(0), d)
}

func TestRandDuration_Positive(t *testing.T) {
	maximum := 100 * time.Millisecond
	for range 100 {
		d := randDuration(maximum)
		assert.True(t, d >= 0, "duration should be non-negative")
		assert.True(t, d < maximum, "duration should be less than max")
	}
}
