package main

import "strings"

// privateWindowsDescriptor accepts allow ACEs only for the exact owner,
// LocalSystem, and built-in administrators. It rejects malformed, empty, null,
// and unexpectedly delegated DACLs rather than trying to enumerate a few broad
// well-known groups.
func privateWindowsDescriptor(sddl string) bool {
	owner := sddlSection(sddl, "O:")
	return privateWindowsDescriptorForOwner(sddl, owner)
}

func privateWindowsDescriptorForOwner(sddl, expectedOwner string) bool {
	owner := sddlSection(sddl, "O:")
	dacl := sddlSection(sddl, "D:")
	if owner == "" || owner != expectedOwner || dacl == "" || strings.Contains(dacl, "NO_ACCESS_CONTROL") {
		return false
	}
	allowed := map[string]bool{owner: true, "SY": true, "BA": true}
	foundAllow := false
	for len(dacl) > 0 {
		start := strings.IndexByte(dacl, '(')
		if start < 0 {
			break
		}
		end := strings.IndexByte(dacl[start:], ')')
		if end < 0 {
			return false
		}
		ace := dacl[start+1 : start+end]
		fields := strings.Split(ace, ";")
		if len(fields) != 6 || fields[0] == "" || fields[5] == "" {
			return false
		}
		if fields[0] == "A" || fields[0] == "OA" {
			foundAllow = true
			if !allowed[fields[5]] {
				return false
			}
		}
		dacl = dacl[start+end+1:]
	}
	return foundAllow
}

func sddlSection(sddl, marker string) string {
	start := strings.Index(sddl, marker)
	if start < 0 {
		return ""
	}
	value := sddl[start+len(marker):]
	end := len(value)
	for _, next := range []string{"O:", "G:", "D:", "S:"} {
		if index := strings.Index(value, next); index >= 0 && index < end {
			end = index
		}
	}
	return value[:end]
}
