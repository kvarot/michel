package notify

import (
	"context"
	"strings"
	"testing"

	"github.com/kvarot/michel/internal/i18n"
	"github.com/kvarot/michel/internal/policy"
)

func TestNotifyFixWaitingHasNoDetail(t *testing.T) {
	r := &captureRunner{}
	n, err := New(policy.ChannelConfig{Name: "bureau", Type: "toast"}, Deps{Runner: r, Lang: i18n.FR})
	if err != nil {
		t.Fatal(err)
	}
	var gotTitle, gotBody string
	n.(*toast).command = func(title, body string) (string, []string, []byte, error) {
		gotTitle, gotBody = title, body
		return "fake-toast", nil, nil, nil
	}
	out := SendFixWaiting(context.Background(), []Notifier{n}, 2, "http://127.0.0.1:7331/")
	if len(out) != 1 || out[0].Result != ResultOK {
		t.Fatalf("deliveries = %+v", out)
	}
	if gotTitle != "Michel · une correction t'attend" || !strings.Contains(gotBody, "2 corrections attendent ta décision") || !strings.Contains(gotBody, "http://127.0.0.1:7331/") {
		t.Errorf("title %q body %q", gotTitle, gotBody)
	}
	// Nothing but the count and the link: no project, package, path, diff.
	for _, forbidden := range []string{"demo", "acme", "composer", "/", "\\", "+++"} {
		if strings.Contains(strings.ReplaceAll(gotBody, "http://127.0.0.1:7331/", ""), forbidden) {
			t.Errorf("body holds %q: %q", forbidden, gotBody)
		}
	}
	title, body := fixWaitingMessage(i18n.EN, 1, "")
	if title != "Michel · a fix waits for you" || body != "1 fix waits for your decision. Open the page to read it." {
		t.Errorf("EN message = %q %q", title, body)
	}
}
