// Copyright 2025 Interlynk.io
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import "github.com/interlynk-io/sbomdelta/pkg/vuln"

// Config holds all user inputs for a single delta evaluation run.
type Config struct {
	UpstreamSBOMPath string
	// UpstreamSBOMFormat SBOMFormat

	HardenedSBOMPath string
	// HardenedSBOMFormat SBOMFormat

	UpstreamVulnPath   string
	UpstreamVulnFormat vuln.VulnFormat

	HardenedVulnPath   string
	HardenedVulnFormat vuln.VulnFormat

	BackportVulnPath   string
	BackportVulnFormat vuln.VulnFormat
}
