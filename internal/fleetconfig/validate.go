package fleetconfig

import (
	"bytes"
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

var (
	entryNamePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]{0,62}[a-z0-9])?$`)
	agentsSuffix     = "AGENTS.md"
)

// Validate enforces the v1 source-tree contract.
func Validate(tree Tree) error {
	if len(tree.Files) == 0 || len(tree.Files) > MaxFiles {
		return errors.New("fleet-config source layout is invalid")
	}
	var total int64
	seen := map[string]struct{}{}
	folded := map[string]struct{}{}
	hasGlobalAgents := false
	skills := map[string]struct{}{}
	dataSkills := map[string]struct{}{}
	for _, file := range tree.Files {
		path, err := canonicalPath(file.Path)
		if err != nil {
			return err
		}
		if _, exists := seen[path]; exists {
			return errors.New("fleet-config source contains a duplicate path")
		}
		lower := strings.ToLower(path)
		if _, exists := folded[lower]; exists {
			return errors.New("fleet-config source contains a case-colliding path")
		}
		seen[path] = struct{}{}
		folded[lower] = struct{}{}
		if int64(len(file.Data)) > MaxFileBytes {
			return errors.New("fleet-config file is too large")
		}
		total += int64(len(file.Data))
		if total > MaxTotalBytes {
			return errors.New("fleet-config source is too large")
		}
		kind, err := classifyPath(path)
		if err != nil {
			return err
		}
		switch kind.class {
		case pathGlobalAgents, pathProjectAgents:
			if err := validateAgents(file.Data); err != nil {
				return err
			}
			if kind.class == pathGlobalAgents {
				hasGlobalAgents = true
			}
		case pathSkillMarkdown:
			if err := validateSkillMarkdown(kind.skill, file.Data); err != nil {
				return err
			}
			skills[kind.skillKey] = struct{}{}
		case pathSkillData:
			if bytes.Contains(file.Data, []byte{0}) && isTextPath(path) {
				return errors.New("fleet-config text file is invalid")
			}
			dataSkills[kind.skillKey] = struct{}{}
		}
	}
	if !hasGlobalAgents || total < 1 {
		if !hasGlobalAgents {
			return errors.New("fleet-config source requires AGENTS.md")
		}
		return errors.New("fleet-config source layout is invalid")
	}
	for key := range dataSkills {
		if _, ok := skills[key]; !ok {
			return errors.New("fleet-config skill path is invalid")
		}
	}
	if len(skills) > MaxSkills {
		return errors.New("fleet-config source has too many skills")
	}
	return nil
}

type pathClass int

const (
	pathGlobalAgents pathClass = iota
	pathProjectAgents
	pathSkillMarkdown
	pathSkillData
)

type classifiedPath struct {
	class    pathClass
	skill    string
	skillKey string
}

func classifyPath(path string) (classifiedPath, error) {
	if path == agentsSuffix {
		return classifiedPath{class: pathGlobalAgents}, nil
	}
	switch {
	case strings.HasPrefix(path, "skills/"):
		skill, rest, ok := splitFirst(strings.TrimPrefix(path, "skills/"))
		if !ok || !entryNamePattern.MatchString(skill) || rest == "" {
			return classifiedPath{}, errors.New("fleet-config skill path is invalid")
		}
		if rest == "SKILL.md" {
			return classifiedPath{class: pathSkillMarkdown, skill: skill, skillKey: "./skills/" + skill}, nil
		}
		if _, err := canonicalPath(rest); err != nil {
			return classifiedPath{}, err
		}
		return classifiedPath{class: pathSkillData, skill: skill, skillKey: "./skills/" + skill}, nil
	case strings.HasPrefix(path, "projects/"):
		project, rest, ok := splitFirst(strings.TrimPrefix(path, "projects/"))
		if !ok || !entryNamePattern.MatchString(project) || rest == "" {
			return classifiedPath{}, errors.New("fleet-config project path is invalid")
		}
		if rest == agentsSuffix {
			return classifiedPath{class: pathProjectAgents}, nil
		}
		if strings.HasPrefix(rest, "skills/") {
			skill, skillRest, skillOK := splitFirst(strings.TrimPrefix(rest, "skills/"))
			if !skillOK || !entryNamePattern.MatchString(skill) || skillRest == "" {
				return classifiedPath{}, errors.New("fleet-config skill path is invalid")
			}
			if skillRest == "SKILL.md" {
				return classifiedPath{class: pathSkillMarkdown, skill: skill, skillKey: project + "/" + skill}, nil
			}
			if _, err := canonicalPath(skillRest); err != nil {
				return classifiedPath{}, err
			}
			return classifiedPath{class: pathSkillData, skill: skill, skillKey: project + "/" + skill}, nil
		}
		return classifiedPath{}, errors.New("fleet-config source layout is invalid")
	default:
		return classifiedPath{}, errors.New("fleet-config source layout is invalid")
	}
}

func validateAgents(data []byte) error {
	if !utf8.Valid(data) || bytes.Contains(data, []byte{0}) {
		return errors.New("fleet-config text file is invalid")
	}
	if bytes.Contains(data, []byte(TrailerStart)) || bytes.Contains(data, []byte(TrailerEnd)) {
		return errors.New("fleet-config source must not contain a machine-local trailer")
	}
	return nil
}

func validateSkillMarkdown(directory string, data []byte) error {
	if !utf8.Valid(data) || bytes.Contains(data, []byte{0}) {
		return errors.New("fleet-config text file is invalid")
	}
	name, description, err := parseSkillFrontmatter(data)
	if err != nil || name != directory || description == "" {
		return errors.New("fleet-config skill metadata is invalid")
	}
	return nil
}

func parseSkillFrontmatter(data []byte) (string, string, error) {
	text := string(data)
	if !strings.HasPrefix(text, "---\n") && !strings.HasPrefix(text, "---\r\n") {
		return "", "", errors.New("missing frontmatter")
	}
	rest := text[3:]
	if strings.HasPrefix(rest, "\r\n") {
		rest = rest[2:]
	} else if strings.HasPrefix(rest, "\n") {
		rest = rest[1:]
	}
	end := strings.Index(rest, "\n---")
	if end < 0 {
		return "", "", errors.New("missing frontmatter")
	}
	body := rest[:end]
	name := ""
	description := ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimRight(line, "\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return "", "", errors.New("missing frontmatter")
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" || strings.ContainsAny(key, " \t") {
			return "", "", errors.New("missing frontmatter")
		}
		if unclosedScalar(value) {
			return "", "", errors.New("missing frontmatter")
		}
		switch key {
		case "name":
			name = value
		case "description":
			description = value
		}
	}
	if name == "" || description == "" {
		return "", "", errors.New("missing frontmatter fields")
	}
	return name, description, nil
}

func unclosedScalar(value string) bool {
	if strings.HasPrefix(value, "[") && !strings.HasSuffix(value, "]") {
		return true
	}
	if strings.HasPrefix(value, "{") && !strings.HasSuffix(value, "}") {
		return true
	}
	if strings.HasPrefix(value, "\"") && !strings.HasSuffix(value, "\"") {
		return true
	}
	if strings.HasPrefix(value, "'") && !strings.HasSuffix(value, "'") {
		return true
	}
	return false
}

func isTextPath(path string) bool {
	return strings.HasSuffix(path, ".md") || strings.HasSuffix(path, ".txt")
}
