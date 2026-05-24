//go:build darwin

package paths

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

var pathHelperRE = regexp.MustCompile(`PATH="([^"]+)"`)

// EnsureMacOSGUIPath merges standard CLI locations into PATH. GUI-launched
// apps (Finder, open -a) often inherit a minimal PATH that omits Homebrew
// and ~/.local/bin, so exec.LookPath("op") fails even when the CLI is installed.
func EnsureMacOSGUIPath() {
	merged := os.Getenv("PATH")
	if p := pathFromHelper(); p != "" {
		merged = mergePathLists(p, merged)
	}
	home, _ := os.UserHomeDir()
	for _, dir := range []string{
		"/opt/homebrew/bin",
		"/usr/local/bin",
		filepath.Join(home, ".local", "bin"),
	} {
		merged = prependPathDir(merged, dir)
	}
	if merged != "" {
		_ = os.Setenv("PATH", merged)
	}
}

func pathFromHelper() string {
	out, err := exec.Command("/usr/libexec/path_helper", "-s").CombinedOutput()
	if err != nil {
		return ""
	}
	m := pathHelperRE.FindSubmatch(out)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

func mergePathLists(primary, secondary string) string {
	seen := make(map[string]struct{})
	var out []string
	for _, list := range []string{primary, secondary} {
		for _, dir := range strings.Split(list, ":") {
			dir = strings.TrimSpace(dir)
			if dir == "" {
				continue
			}
			if _, ok := seen[dir]; ok {
				continue
			}
			seen[dir] = struct{}{}
			out = append(out, dir)
		}
	}
	return strings.Join(out, ":")
}

func prependPathDir(pathList, dir string) string {
	dir = filepath.Clean(dir)
	if dir == "" || dir == "." {
		return pathList
	}
	for _, part := range strings.Split(pathList, ":") {
		if part == dir {
			return pathList
		}
	}
	if pathList == "" {
		return dir
	}
	return dir + ":" + pathList
}
