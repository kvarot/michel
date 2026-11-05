package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// The digest loop and the alerts read the policy while a consent of the page
// reloads it: every read must see one whole policy, the old or the new, and
// the reader goes through the accessor.
func TestPolicyReloadUnderConcurrentReads(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	write := func(at, name string) {
		body := "assistant:\n  name: " + name + "\nnotify:\n  digest_at: \"" + at + "\"\n"
		if err := os.WriteFile(cfg, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("06:00", "Six")
	deps := &Deps{Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}, Now: time.Now}
	t.Cleanup(func() { deps.Close() })
	root := NewRootCmd(deps)
	root.AddCommand(&cobra.Command{Use: "reload", RunE: func(cmd *cobra.Command, _ []string) error {
		reload := sourceDeps(cmd, deps).Reload
		stop := make(chan struct{})
		var wg sync.WaitGroup
		var mu sync.Mutex
		var bad []string
		for i := 0; i < 4; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for {
					select {
					case <-stop:
						return
					default:
					}
					p := deps.Policy()
					pair := p.Notify.DigestAt + "/" + p.Assistant.Name
					if pair != "06:00/Six" && pair != "09:00/Nine" {
						mu.Lock()
						bad = append(bad, pair)
						mu.Unlock()
					}
				}
			}()
		}
		for i := 0; i < 50; i++ {
			if i%2 == 0 {
				write("09:00", "Nine")
			} else {
				write("06:00", "Six")
			}
			if _, err := reload(); err != nil {
				close(stop)
				wg.Wait()
				return err
			}
		}
		close(stop)
		wg.Wait()
		if len(bad) > 0 {
			t.Errorf("mixed policies read: %v", bad[:min(len(bad), 5)])
		}
		if got := deps.Policy().Notify.DigestAt; got != "06:00" {
			t.Errorf("last reload not in force: %q", got)
		}
		return nil
	}})
	root.SetArgs([]string{"--config", cfg, "--data-dir", dir, "reload"})
	if err := root.Execute(); err != nil {
		t.Fatal(err)
	}
}
