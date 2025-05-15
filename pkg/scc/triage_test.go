package scc

import (
	"testing"

	sccv2pb "cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	triage "github.com/ca-risken/core/pkg/server/finding"
	"github.com/ca-risken/vulnerability/pkg/model"
	"github.com/google/go-cmp/cmp"
)

func TestEvaluateVulnerability(t *testing.T) {
	tests := []struct {
		name             string
		vuln             *model.Vulnerability
		wantExploitation *triage.Exploitation
		wantUtility      *triage.Utility
	}{
		{
			name:             "empty",
			vuln:             &model.Vulnerability{},
			wantExploitation: nil,
			wantUtility:      nil,
		},
		{
			name: "kev",
			vuln: &model.Vulnerability{
				CVE: &model.CVEData{
					CVEDataMeta: model.CVEDataMetaData{
						ID: "CVE-9999-12345",
					},
				},
				KEV: &model.KEV{
					CveID: model.Ptr("KEV-9999-12345"),
				},
			},
			wantExploitation: &triage.Exploitation{
				HasCVE:    triage.Ptr(true),
				HasKEV:    triage.Ptr(true),
				PublicPOC: triage.Ptr(false),
				EpssScore: triage.Ptr(float32(0)),
			},
			wantUtility: &triage.Utility{
				Automatable:  triage.Ptr(triage.AUTOMATABLE_NO),
				ValueDensity: triage.Ptr(triage.TRIAGE_UNKNOWN),
			},
		},
		{
			name: "poc_epss",
			vuln: &model.Vulnerability{
				CVE: &model.CVEData{
					CVEDataMeta: model.CVEDataMetaData{
						ID: "CVE-9999-12345",
					},
				},
				PoC: []*model.PoC{
					{
						CVEID: "CVE-9999-12345",
					},
				},
				EPSS: model.Ptr(0.75),
			},
			wantExploitation: &triage.Exploitation{
				HasCVE:    triage.Ptr(true),
				HasKEV:    triage.Ptr(false),
				PublicPOC: triage.Ptr(true),
				EpssScore: triage.Ptr(float32(0.75)),
			},
			wantUtility: &triage.Utility{
				Automatable:  triage.Ptr(triage.AUTOMATABLE_YES),
				ValueDensity: triage.Ptr(triage.TRIAGE_UNKNOWN),
			},
		},
		{
			name: "all",
			vuln: &model.Vulnerability{
				CVE: &model.CVEData{
					CVEDataMeta: model.CVEDataMetaData{
						ID: "CVE-9999-12345",
					},
				},
				KEV: &model.KEV{
					CveID: model.Ptr("KEV-9999-12345"),
				},
				PoC: []*model.PoC{
					{
						CVEID: "CVE-9999-12345",
					},
				},
				EPSS: model.Ptr(0.25),
			},
			wantExploitation: &triage.Exploitation{
				HasCVE:    triage.Ptr(true),
				HasKEV:    triage.Ptr(true),
				PublicPOC: triage.Ptr(true),
				EpssScore: triage.Ptr(float32(0.25)),
			},
			wantUtility: &triage.Utility{
				Automatable:  triage.Ptr(triage.AUTOMATABLE_YES),
				ValueDensity: triage.Ptr(triage.TRIAGE_UNKNOWN),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotExploitation, gotUtility := evaluateVulnerability(tc.vuln)
			if diff := cmp.Diff(tc.wantExploitation, gotExploitation); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantUtility, gotUtility); diff != "" {
				t.Errorf("mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestEvaluateAttackExposure(t *testing.T) {
	tests := []struct {
		name               string
		attackExposure     *sccv2pb.AttackExposure
		wantSystemExposure *triage.SystemExposure
		wantHumanImpact    *triage.HumanImpact
	}{
		{
			name:               "nil",
			attackExposure:     nil,
			wantSystemExposure: nil,
			wantHumanImpact:    nil,
		},
		{
			name: "not_calculated",
			attackExposure: &sccv2pb.AttackExposure{
				State: sccv2pb.AttackExposure_NOT_CALCULATED,
			},
			wantSystemExposure: nil,
			wantHumanImpact:    nil,
		},
		{
			name: "no_exposure",
			attackExposure: &sccv2pb.AttackExposure{
				State:                            sccv2pb.AttackExposure_CALCULATED,
				Score:                            0,
				ExposedHighValueResourcesCount:   0,
				ExposedMediumValueResourcesCount: 0,
			},
			wantSystemExposure: &triage.SystemExposure{
				PublicFacing:  triage.Ptr(string(triage.PUBLIC_FACING_INTERNAL)),
				AccessControl: triage.Ptr(string(triage.ACCESS_CONTROL_NONE)),
			},
			wantHumanImpact: &triage.HumanImpact{
				SafetyImpact:  triage.Ptr(triage.SAFETY_IMPACT_NEGLIGIBLE),
				MissionImpact: triage.Ptr(triage.MISSION_IMPACT_DEGRADED),
			},
		},
		{
			name: "with_exposure",
			attackExposure: &sccv2pb.AttackExposure{
				State:                            sccv2pb.AttackExposure_CALCULATED,
				Score:                            0.5,
				ExposedHighValueResourcesCount:   1,
				ExposedMediumValueResourcesCount: 2,
			},
			wantSystemExposure: &triage.SystemExposure{
				PublicFacing:  triage.Ptr(triage.PUBLIC_FACING_OPEN),
				AccessControl: triage.Ptr(triage.ACCESS_CONTROL_NONE),
			},
			wantHumanImpact: &triage.HumanImpact{
				SafetyImpact:  triage.Ptr(triage.TRIAGE_UNKNOWN),
				MissionImpact: triage.Ptr(triage.TRIAGE_UNKNOWN),
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotSystemExposure, gotHumanImpact := evaluateAttackExposure(tc.attackExposure)
			if diff := cmp.Diff(tc.wantSystemExposure, gotSystemExposure); diff != "" {
				t.Errorf("systemExposure mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tc.wantHumanImpact, gotHumanImpact); diff != "" {
				t.Errorf("humanImpact mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
