package integrations

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/yominsops/yomins-agent/internal/metrics"
)

// MailQueue counts the messages waiting in Exim's or Postfix's queue by
// reading the spool directories (exim -bpc / mailq need root). A growing
// queue means mail is not leaving: a blacklisted IP, a broken relay, spam
// sent from a hacked site.
type MailQueue struct {
	root string
}

// NewMailQueue creates the integration.
func NewMailQueue(root string) *MailQueue { return &MailQueue{root: root} }

func (m *MailQueue) Name() string { return "mail_queue" }

func (m *MailQueue) Collect(_ context.Context) ([]metrics.MetricPoint, error) {
	var pts []metrics.MetricPoint
	for _, spool := range []string{"var/spool/exim4/input", "var/spool/exim/input"} {
		dir := filepath.Join(m.root, spool)
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		n, err := countFiles(dir, func(name string) bool { return strings.HasSuffix(name, "-H") })
		if err != nil {
			pts = append(pts, status("mail_queue", StatusError, "exim"))
			break
		}
		pts = append(pts, status("mail_queue", StatusOK, "exim"),
			gauge("mail_queue_messages", "Messages in the mail queue", float64(n), map[string]string{"mta": "exim", "queue": "all"}))
		break
	}
	pf := filepath.Join(m.root, "var/spool/postfix")
	if _, err := os.Stat(pf); err == nil {
		ok := true
		for _, q := range []string{"incoming", "active", "deferred", "hold"} {
			n, err := countFiles(filepath.Join(pf, q), func(string) bool { return true })
			if err != nil {
				ok = false
				continue
			}
			pts = append(pts, gauge("mail_queue_messages", "Messages in the mail queue", float64(n), map[string]string{"mta": "postfix", "queue": q}))
		}
		if ok {
			pts = append(pts, status("mail_queue", StatusOK, "postfix"))
		} else {
			pts = append(pts, status("mail_queue", StatusError, "postfix"))
		}
	}
	return pts, nil
}

func countFiles(dir string, match func(string) bool) (int, error) {
	n := 0
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && match(d.Name()) {
			n++
		}
		return nil
	})
	return n, err
}
