package scc

import (
	sccv2pb "cloud.google.com/go/securitycenter/apiv2/securitycenterpb"
	triage "github.com/ca-risken/core/pkg/server/finding"
	"github.com/ca-risken/vulnerability/pkg/model"
)

func Triage(vuln *model.Vulnerability, attackExposure *sccv2pb.AttackExposure) *triage.RiskenTriage {
	source := triage.TriageSource{}

	// evaluate vulnerability
	if vuln != nil {
		exploitation, utility := evaluateVulnerability(vuln)
		source.Exploitation = exploitation
		source.Utility = utility
	}

	// evaluate attack exposure
	if attackExposure != nil {
		systemExposure, humanImpact := evaluateAttackExposure(attackExposure)
		source.SystemExposure = systemExposure
		source.HumanImpact = humanImpact
	}

	if source.Exploitation != nil || source.SystemExposure != nil || source.HumanImpact != nil {
		return &triage.RiskenTriage{
			Source: &source,
		}
	}
	return nil
}

func evaluateVulnerability(vuln *model.Vulnerability) (*triage.Exploitation, *triage.Utility) {
	hasCVE := false
	if vuln.CVE != nil && vuln.CVE.CVEDataMeta.ID != "" {
		hasCVE = true
	} else {
		return nil, nil
	}
	hasKEV := false
	if vuln.KEV != nil {
		hasKEV = true
	}
	publicPOC := false
	automatable := triage.AUTOMATABLE_NO
	if vuln.PoC != nil {
		publicPOC = true
		automatable = triage.AUTOMATABLE_YES
	}
	epssScore := float32(0.0)
	if vuln.EPSS != nil {
		epssScore = float32(*vuln.EPSS)
	}

	exploitation := &triage.Exploitation{
		HasCVE:    triage.Ptr(hasCVE),
		HasKEV:    triage.Ptr(hasKEV),
		PublicPOC: triage.Ptr(publicPOC),
		EpssScore: triage.Ptr(epssScore),
	}
	utility := &triage.Utility{
		Automatable:  triage.Ptr(automatable),
		ValueDensity: triage.Ptr(triage.TRIAGE_UNKNOWN),
	}
	return exploitation, utility
}

func evaluateAttackExposure(attackExposure *sccv2pb.AttackExposure) (*triage.SystemExposure, *triage.HumanImpact) {
	if attackExposure == nil {
		return nil, nil
	}
	if attackExposure.State != sccv2pb.AttackExposure_CALCULATED {
		return nil, nil
	}

	// system exposure
	systemExposure := triage.SystemExposure{
		PublicFacing:  triage.Ptr(triage.TRIAGE_UNKNOWN),
		AccessControl: triage.Ptr(triage.TRIAGE_UNKNOWN),
	}
	if attackExposure.Score > 0 {
		systemExposure.PublicFacing = triage.Ptr(triage.PUBLIC_FACING_OPEN)
		systemExposure.AccessControl = triage.Ptr(triage.ACCESS_CONTROL_NONE)
	} else {
		systemExposure.PublicFacing = triage.Ptr(string(triage.PUBLIC_FACING_INTERNAL))
		systemExposure.AccessControl = triage.Ptr(string(triage.ACCESS_CONTROL_NONE))
	}

	// human impact
	humanImpact := triage.HumanImpact{
		SafetyImpact:  triage.Ptr(triage.TRIAGE_UNKNOWN),
		MissionImpact: triage.Ptr(triage.TRIAGE_UNKNOWN),
	}
	if attackExposure.ExposedHighValueResourcesCount == 0 && attackExposure.ExposedMediumValueResourcesCount == 0 {
		humanImpact.SafetyImpact = triage.Ptr(triage.SAFETY_IMPACT_NEGLIGIBLE)
		humanImpact.MissionImpact = triage.Ptr(triage.MISSION_IMPACT_DEGRADED)
	}
	return &systemExposure, &humanImpact
}
