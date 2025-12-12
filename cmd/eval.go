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

package cmd

import (
	"github.com/spf13/cobra"

	"github.com/interlynk-io/sbomdelta/pkg/delta"
	"github.com/interlynk-io/sbomdelta/pkg/types"
	"github.com/interlynk-io/sbomdelta/pkg/vuln"
)

var (
	flagUpSBOM       string
	flagUpSBOMFormat string
	flagHdSBOM       string
	flagHdSBOMFormat string

	flagUpVuln       string
	flagUpVulnFormat string
	flagHdVuln       string
	flagHdVulnFormat string

	flagBcVuln       string
	flagBcVulnFormat string
)

var evalCmd = &cobra.Command{
	Use:   "eval",
	Short: "Evaluate CVE delta between upstream and hardened images",
	Example: `
  delta eval \
    --up-sbom=upstream-sbom.cdx.json \
    --hd-sbom=hardened-sbom.cdx.json \
    --up-vuln=upstream-vuln.json \
    --hd-vuln=hardened-vuln.json`,
	RunE: runEval,
}

func runEval(cmd *cobra.Command, args []string) error {
	cfg, err := buildConfigFromFlags()
	if err != nil {
		return err
	}
	return delta.RunEval(cmd.Context(), cfg)
}

func buildConfigFromFlags() (*types.Config, error) {
	cfg := &types.Config{
		UpstreamSBOMPath: flagUpSBOM,
		HardenedSBOMPath: flagHdSBOM,
		UpstreamVulnPath: flagUpVuln,
		HardenedVulnPath: flagHdVuln,
		BackportVulnPath: flagBcVuln,
	}

	var err error

	cfg.UpstreamVulnFormat, err = vuln.ParseVulnFormat(flagUpVulnFormat)
	if err != nil {
		return nil, err
	}
	cfg.HardenedVulnFormat, err = vuln.ParseVulnFormat(flagHdVulnFormat)
	if err != nil {
		return nil, err
	}

	if flagBcVuln != "" {
		cfg.BackportVulnFormat, err = vuln.ParseVulnFormat(flagBcVulnFormat)
		if err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

func init() {
	// SBOM inputs
	evalCmd.Flags().StringVar(&flagUpSBOM, "up-sbom", "", "Path to upstream SBOM (CycloneDX or SPDX JSON)")
	evalCmd.Flags().StringVar(&flagUpSBOMFormat, "up-sbom-format", "cyclonedx", "Upstream SBOM format: cyclonedx | spdx")

	evalCmd.Flags().StringVar(&flagHdSBOM, "hd-sbom", "", "Path to hardened SBOM (CycloneDX or SPDX JSON)")
	evalCmd.Flags().StringVar(&flagHdSBOMFormat, "hd-sbom-format", "cyclonedx", "Hardened SBOM format: cyclonedx | spdx")

	// Vulnerability inputs
	evalCmd.Flags().StringVar(&flagUpVuln, "up-vuln", "", "Path to upstream vulnerability report (Trivy or Grype JSON)")
	evalCmd.Flags().StringVar(&flagUpVulnFormat, "up-vuln-format", "trivy", "Upstream vuln format: trivy | grype")

	evalCmd.Flags().StringVar(&flagHdVuln, "hd-vuln", "", "Path to hardened vulnerability report (Trivy or Grype JSON)")
	evalCmd.Flags().StringVar(&flagHdVulnFormat, "hd-vuln-format", "trivy", "Hardened vuln format: trivy | grype")

	// Optional backport / exception vuln file
	evalCmd.Flags().StringVar(&flagBcVuln, "bc-vuln", "", "Optional backport/exception vulnerability file (Trivy or Grype JSON)")
	evalCmd.Flags().StringVar(&flagBcVulnFormat, "bc-vuln-format", "trivy", "Backport vuln format: trivy | grype")

	// Mark required flags
	_ = evalCmd.MarkFlagRequired("up-sbom")
	_ = evalCmd.MarkFlagRequired("hd-sbom")
	_ = evalCmd.MarkFlagRequired("up-vuln")
	_ = evalCmd.MarkFlagRequired("hd-vuln")
}
