package version

import "fmt"

var (
	Version = "1.0.0"
	Commit  = "unknown"
	Date    = "unknown"
)

func String() string {
	return fmt.Sprintf("%s (commit=%s date=%s)", Version, Commit, Date)
}
