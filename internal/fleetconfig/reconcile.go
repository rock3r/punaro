package fleetconfig

import "strings"

// PrepareApply builds the live file set from a validated tree, applying trailers.
func PrepareApply(tree Tree, existing map[string][]byte, lastPrefixDigests map[string]string) (map[string][]byte, map[string]TrailerResult, error) {
	if err := Validate(tree); err != nil {
		return nil, nil, err
	}
	files := make(map[string][]byte, len(tree.Files))
	trailers := map[string]TrailerResult{}
	for _, file := range tree.Files {
		if stringsHasSuffixAgents(file.Path) {
			live, ok := existing[file.Path]
			next, result, err := ApplyAgents(file.Data, live, ok, lastPrefixDigests[file.Path])
			if err != nil {
				return nil, nil, err
			}
			trailers[file.Path] = result
			if result.Collision {
				continue
			}
			files[file.Path] = next
			continue
		}
		files[file.Path] = file.Data
	}
	return files, trailers, nil
}

func stringsHasSuffixAgents(path string) bool {
	return path == "AGENTS.md" || strings.HasSuffix(path, "/AGENTS.md")
}
