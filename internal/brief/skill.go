package brief

import (
	"fmt"
	"path/filepath"

	"github.com/kvarot/michel/internal/gitrepo"
	"github.com/kvarot/michel/internal/i18n"
)

// SkillKey is the owner key written in the marker of a finding's skill.
func SkillKey(findingID string) string { return "fix:" + findingID }

// SkillName is the folder and skill name for a finding: michel-fix- and the
// first 8 characters of its id.
func SkillName(findingID string) (string, error) {
	id, err := shortID(findingID)
	if err != nil {
		return "", err
	}
	return "michel-fix-" + id, nil
}

// WriteSkill writes the Claude Code skill of the brief in
// skillsDir/michel-fix-<id>/SKILL.md, with the marker of Michel, and returns
// the folder. The body is the brief plus a closing section that tells Claude
// Code to report through the propose_fix tool of the michel MCP server. A
// folder of that name that Michel did not write is refused
// (gitrepo.ErrForeignDir) and left as it is.
func WriteSkill(skillsDir string, b Brief, lang i18n.Lang) (string, error) {
	name, err := SkillName(b.FindingID)
	if err != nil {
		return "", err
	}
	lang = langOf(lang)
	front := frontMatter(b)
	skill := fmt.Sprintf("---\nname: %s\ndescription: %s\n---\n", name,
		yamlStr(i18n.T(lang, "brief.skill.description", clean(b.Package), clean(b.OSVID)))) +
		"```yaml\n" + front + "```\n\n" + body(b, lang) + "\n" + footer(lang)
	dir := filepath.Join(skillsDir, name)
	if err := gitrepo.WriteOwnedDir(dir, SkillKey(b.FindingID), map[string][]byte{"SKILL.md": []byte(skill)}); err != nil {
		return "", err
	}
	return dir, nil
}

// RemoveSkill removes the skill of a finding when Michel wrote it; a folder
// of that name without Michel's marker, or a missing one, is left alone.
func RemoveSkill(skillsDir, findingID string) error {
	name, err := SkillName(findingID)
	if err != nil {
		return err
	}
	_, err = gitrepo.RemoveOwnedDir(filepath.Join(skillsDir, name), SkillKey(findingID))
	return err
}
