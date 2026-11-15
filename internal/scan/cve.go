package scan

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"sort"
	"strings"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
)

// CVEScanner scans one image for known vulnerabilities and baked-in secrets.
type CVEScanner interface {
	Available() bool
	Scan(ctx context.Context, ref, imageID string) *model.ImageScan
}

// TrivyScanner shells out to a pinned Trivy binary.
type TrivyScanner struct {
	Bin        string
	DockerHost string
	CacheDir   string
	Timeout    time.Duration
}

func (t *TrivyScanner) Available() bool {
	if t == nil || t.Bin == "" {
		return false
	}
	_, err := exec.LookPath(t.Bin)
	return err == nil
}

type trivyReport struct {
	Results []struct {
		Target          string
		Vulnerabilities []struct {
			VulnerabilityID  string
			PkgName          string
			InstalledVersion string
			FixedVersion     string
			Severity         string
			Title            string
		}
		Secrets []struct {
			RuleID   string
			Category string
			Title    string
			Severity string
		}
	}
}

func (t *TrivyScanner) Scan(ctx context.Context, ref, imageID string) *model.ImageScan {
	res := &model.ImageScan{ImageID: imageID, Ref: ref, ScannedAt: time.Now().UTC(), Counts: map[string]int{}}
	to := t.Timeout
	if to == 0 {
		to = 15 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	args := []string{"image", "--quiet", "--format", "json", "--scanners", "vuln,secret",
		"--skip-version-check", "--timeout", to.String()}
	if t.CacheDir != "" {
		args = append(args, "--cache-dir", t.CacheDir)
	}
	if t.DockerHost != "" {
		args = append(args, "--docker-host", t.DockerHost)
	}
	args = append(args, ref)
	cmd := exec.CommandContext(ctx, t.Bin, args...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		res.Error = fmt.Sprintf("trivy: %v: %s", err, truncate(strings.TrimSpace(errb.String()), 300))
		return res
	}
	var rep trivyReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		res.Error = "trivy output: " + err.Error()
		return res
	}
	seen := map[string]bool{}
	for _, r := range rep.Results {
		for _, v := range r.Vulnerabilities {
			key := v.VulnerabilityID + v.PkgName
			if seen[key] {
				continue
			}
			seen[key] = true
			sev := model.Severity(strings.ToLower(v.Severity))
			if sev == "unknown" || sev == "" {
				sev = model.SevInfo
			}
			res.Counts[string(sev)]++
			if v.FixedVersion != "" {
				res.Fixable++
			}
			res.CVEs = append(res.CVEs, model.CVE{ID: v.VulnerabilityID, Pkg: v.PkgName, Installed: v.InstalledVersion,
				Fixed: v.FixedVersion, Severity: sev, Title: truncate(v.Title, 140)})
		}
		for _, s := range r.Secrets {
			res.Secrets = append(res.Secrets, fmt.Sprintf("%s in %s (%s)", s.Title, r.Target, s.RuleID))
		}
	}
	SortCVEs(res.CVEs)
	if len(res.CVEs) > 200 {
		res.CVEs = res.CVEs[:200]
	}
	return res
}

func SortCVEs(c []model.CVE) {
	sort.SliceStable(c, func(i, j int) bool {
		if c[i].Severity.Rank() != c[j].Severity.Rank() {
			return c[i].Severity.Rank() > c[j].Severity.Rank()
		}
		if (c[i].Fixed != "") != (c[j].Fixed != "") {
			return c[i].Fixed != ""
		}
		return c[i].ID > c[j].ID
	})
}

// ImageScanRules converts a CVE scan into findings on the image.
func ImageScanRules(s *model.ImageScan) []model.Finding {
	if s == nil || s.Error != "" {
		return nil
	}
	b := &fb{tt: model.TargetImage, target: s.Ref, id: s.ImageID}
	crit, high, med := s.Counts["critical"], s.Counts["high"], s.Counts["medium"]
	fixCrit, fixHigh := 0, 0
	var top []string
	for _, c := range s.CVEs {
		if c.Fixed != "" && c.Severity == model.SevCritical {
			fixCrit++
		}
		if c.Fixed != "" && c.Severity == model.SevHigh {
			fixHigh++
		}
		if len(top) < 5 && c.Severity.Rank() >= 3 {
			top = append(top, c.ID+" ("+c.Pkg+")")
		}
	}
	ev := strings.Join(top, ", ")
	fix := "Pull the latest patch release of this image and recreate the container (`docker compose pull && docker compose up -d`). If the vendor has not shipped a fix, switch to a slimmer or hardened base image."
	if crit > 0 {
		b.add("cve-critical", model.CatOutdated, model.SevCritical, "4.4",
			plural(crit, "critical CVE")+fmt.Sprintf(" (%d fixable)", fixCrit),
			"Critical vulnerabilities are present in packages inside this image.", fix, ev)
	}
	if high > 0 {
		b.add("cve-high", model.CatOutdated, model.SevHigh, "4.4",
			plural(high, "high CVE")+fmt.Sprintf(" (%d fixable)", fixHigh),
			"High-severity vulnerabilities are present in this image.", fix, ev)
	}
	if med > 0 && crit == 0 && high == 0 {
		b.add("cve-medium", model.CatOutdated, model.SevLow, "4.4",
			plural(med, "medium CVE"), "Only medium or lower vulnerabilities found.", fix, "")
	}
	for _, sec := range s.Secrets {
		b.addD("image-secret", sec, model.CatCredentials, model.SevCritical, "4.10",
			"Secret baked into image layers",
			"A credential is stored in the image itself. Anyone who can pull the image can extract it, even if a later layer deletes the file.",
			"Rotate the credential, rebuild without it (use build secrets: `RUN --mount=type=secret`), and delete old tags from the registry.", sec)
	}
	return b.out
}

func plural(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("1 %s", noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
