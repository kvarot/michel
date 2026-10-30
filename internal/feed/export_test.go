package feed

// SetGitHubAPIForTest points the GitHub requests at url and returns the
// function that restores the real API.
func SetGitHubAPIForTest(url string) func() {
	old := githubAPI
	githubAPI = url
	return func() { githubAPI = old }
}
