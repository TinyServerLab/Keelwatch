package scan

import (
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/keelwatch/keelwatch/internal/model"
)

// UpdateRules reports images that lag their registry.
func UpdateRules(ref, imageID string, st *model.UpdateStatus, created time.Time, now time.Time) []model.Finding {
	b := &fb{tt: model.TargetImage, target: ref, id: imageID}
	fix := "Pull and recreate: `docker compose pull && docker compose up -d`. Read the release notes first for minor/major bumps."
	if st != nil && st.Error == "" {
		if st.DigestNew {
			b.add("digest-stale", model.CatOutdated, model.SevMedium, "",
				"Newer build published for this tag",
				"The registry has a newer image for `"+ref+"` than the one running. Rebuilt images usually carry OS security patches.",
				fix, "remote "+short(st.RemoteDigs))
		}
		switch st.Bump {
		case "patch":
			b.add("version-behind", model.CatOutdated, model.SevMedium, "",
				"Patch update available: "+st.NewestTag, "Patch releases are usually bug and security fixes and safe to apply.", fix, "newest "+st.NewestTag)
		case "minor":
			b.add("version-behind", model.CatOutdated, model.SevLow, "",
				"Minor update available: "+st.NewestTag, "A newer minor version exists.", fix, "newest "+st.NewestTag)
		case "major":
			b.add("version-behind", model.CatOutdated, model.SevLow, "",
				"Major update available: "+st.NewestTag, "A new major version exists. The current line may stop getting security fixes.", fix, "newest "+st.NewestTag)
		}
	}
	if !created.IsZero() {
		age := now.Sub(created)
		switch {
		case age > 365*24*time.Hour:
			b.add("image-age", model.CatOutdated, model.SevMedium, "",
				fmt.Sprintf("Image is %d days old", int(age.Hours()/24)),
				"Images over a year old almost always contain unpatched OS packages.", fix, created.Format("2006-01-02"))
		case age > 180*24*time.Hour:
			b.add("image-age", model.CatOutdated, model.SevLow, "",
				fmt.Sprintf("Image is %d days old", int(age.Hours()/24)),
				"The base layers are over six months old.", fix, created.Format("2006-01-02"))
		}
	}
	return b.out
}

func short(d string) string {
	if len(d) > 19 {
		return d[:19] + "…"
	}
	return d
}

// smoothScore maps an accumulated penalty to 0..100 without hitting zero
// for a single bad host and without letting many small issues dominate.
func smoothScore(penalty, k float64) int {
	if penalty <= 0 {
		return 100
	}
	return int(math.Round(100 - 100*penalty/(penalty+k)))
}

func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 70:
		return "C"
	case score >= 60:
		return "D"
	}
	return "F"
}

// Score fills overall, per-category and per-container scores.
func Score(snap *model.Snapshot) {
	n := float64(len(snap.Containers))
	if n < 1 {
		n = 1
	}
	var total float64
	hasCritical := false
	catPen := map[model.Category]float64{}
	catCounts := map[model.Category]map[model.Severity]int{}
	catTop := map[model.Category]model.Finding{}
	byContainer := map[string]float64{}
	imageToContainers := map[string][]string{}
	for _, c := range snap.Containers {
		imageToContainers[c.ImageID] = append(imageToContainers[c.ImageID], c.ID)
	}
	for i := range snap.Containers {
		snap.Containers[i].Counts = map[model.Severity]int{}
		snap.Containers[i].ByCat = map[model.Category]int{}
	}
	cIndex := map[string]int{}
	for i, c := range snap.Containers {
		cIndex[c.ID] = i
	}
	for _, f := range snap.Findings {
		if f.Suppressed {
			continue
		}
		w := f.Severity.Weight()
		total += w
		catPen[f.Category] += w
		if catCounts[f.Category] == nil {
			catCounts[f.Category] = map[model.Severity]int{}
		}
		catCounts[f.Category][f.Severity]++
		if t, ok := catTop[f.Category]; !ok || f.Severity.Rank() > t.Severity.Rank() {
			catTop[f.Category] = f
		}
		if f.Severity == model.SevCritical {
			hasCritical = true
		}
		var targets []string
		switch f.TargetType {
		case model.TargetContainer:
			targets = []string{f.TargetID}
		case model.TargetImage:
			targets = imageToContainers[f.TargetID]
		}
		for _, id := range targets {
			byContainer[id] += w
			if i, ok := cIndex[id]; ok {
				snap.Containers[i].Counts[f.Severity]++
				snap.Containers[i].ByCat[f.Category]++
			}
		}
	}
	snap.Score = smoothScore(total, 30+15*n)
	if hasCritical && snap.Score > 69 {
		snap.Score = 69
	}
	snap.Grade = Grade(snap.Score)
	snap.Categories = nil
	for _, c := range model.Categories {
		cs := model.CategoryScore{Category: c, Label: model.CategoryLabels[c], Score: smoothScore(catPen[c], 15+8*n), Counts: catCounts[c]}
		if cs.Counts == nil {
			cs.Counts = map[model.Severity]int{}
		}
		for s, k := range cs.Counts {
			if s != model.SevInfo {
				cs.Count += k
			}
		}
		if t, ok := catTop[c]; ok && t.Severity != model.SevInfo {
			cs.Top = t.Title + " — " + t.Target
		}
		snap.Categories = append(snap.Categories, cs)
	}
	for i := range snap.Containers {
		snap.Containers[i].Score = smoothScore(byContainer[snap.Containers[i].ID], 40)
	}
	snap.Debt = debt(snap.Findings, snap.ScannedAt)
	SortFindings(snap.Findings)
	sort.SliceStable(snap.Containers, func(i, j int) bool { return snap.Containers[i].Score < snap.Containers[j].Score })
}

func SortFindings(fs []model.Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Severity.Rank() != fs[j].Severity.Rank() {
			return fs[i].Severity.Rank() > fs[j].Severity.Rank()
		}
		if fs[i].Category != fs[j].Category {
			return fs[i].Category < fs[j].Category
		}
		return fs[i].Target < fs[j].Target
	})
}

// debt marks overdue findings and summarises their age relative to now.
func debt(fs []model.Finding, now time.Time) model.Debt {
	d := model.Debt{BySeverity: map[model.Severity]int{}, Ages: make([]int, len(model.DebtAges)+1)}
	for i := range fs {
		f := &fs[i]
		f.DueAt, f.Overdue = time.Time{}, false
		within, ok := model.FixWithin[f.Severity]
		if f.Suppressed || !ok || f.FirstSeen.IsZero() {
			continue
		}
		d.Open++
		days := int(now.Sub(f.FirstSeen).Hours() / 24)
		b := 0
		for b < len(model.DebtAges) && days >= model.DebtAges[b] {
			b++
		}
		d.Ages[b]++
		if days > d.OldestDays {
			d.OldestDays = days
		}
		f.DueAt = f.FirstSeen.Add(within)
		if now.After(f.DueAt) {
			f.Overdue = true
			d.Overdue++
			d.BySeverity[f.Severity]++
			d.DebtDays += int(now.Sub(f.DueAt).Hours()/24) + 1
		}
	}
	return d
}
