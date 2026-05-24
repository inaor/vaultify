package buildinfo

// GitHubRepo is the canonical releases source (owner/repo).
// Override at link time for forks: -X ...GitHubRepo=myorg/vaultify
var GitHubRepo = "securityjoes/vaultify"

// LatestManifestURL is the raw JSON manifest on main; bump releases/latest.json on each release.
func LatestManifestURL() string {
	return "https://raw.githubusercontent.com/" + GitHubRepo + "/main/releases/latest.json"
}
