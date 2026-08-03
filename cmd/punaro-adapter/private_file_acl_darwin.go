//go:build darwin

package main

/*
#include <sys/acl.h>
#include <errno.h>

static int punaro_has_extended_acl(int fd) {
	errno = 0;
	acl_t acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED);
	// APFS reports either ENOATTR or ENOENT for a file with no extended ACL.
	if (acl == NULL) return (errno == ENOATTR || errno == ENOENT) ? 0 : 1;
	acl_entry_t entry;
	int result = acl_get_entry(acl, ACL_FIRST_ENTRY, &entry);
	while (result == 0) {
		acl_tag_t tag;
		if (acl_get_tag_type(entry, &tag) != 0 ||
		    tag == ACL_EXTENDED_ALLOW || tag == ACL_EXTENDED_DENY) {
			acl_free(acl);
			return 1;
		}
		result = acl_get_entry(acl, ACL_NEXT_ENTRY, &entry);
	}
	acl_free(acl);
	return 0;
}
*/
import "C"

func hasExtendedACL(fd int) bool {
	return C.punaro_has_extended_acl(C.int(fd)) != 0
}
