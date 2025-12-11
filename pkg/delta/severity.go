package delta

import "strings"

func normalizeSeverity(s string) string {
	up := strings.ToUpper(strings.TrimSpace(s))
	switch up {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return up
	default:
		return "UNKNOWN"
	}
}

func isHighOrCritical(sev string) bool {
	s := normalizeSeverity(sev)
	return s == "HIGH" || s == "CRITICAL"
}
