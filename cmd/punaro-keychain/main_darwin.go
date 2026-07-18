//go:build darwin

// punaro-keychain creates the one local Keychain item used to wrap sender
// attachment file keys. Its secret never crosses an environment variable,
// shell argument, file, or standard stream.
package main

/*
#cgo LDFLAGS: -framework Security -framework CoreFoundation
#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>
#include <stdlib.h>

// add_wrapping_key adds one base64-encoded 32-byte wrapping key to the default
// login Keychain. It returns 0 on creation, 1 when the item already exists,
// and -1 for any other Keychain failure.
static int add_wrapping_key(const char *service, const char *account, const uint8_t *key, size_t key_len) {
	CFStringRef service_string = CFStringCreateWithCString(kCFAllocatorDefault, service, kCFStringEncodingUTF8);
	CFStringRef account_string = CFStringCreateWithCString(kCFAllocatorDefault, account, kCFStringEncodingUTF8);
	CFDataRef key_data = CFDataCreate(kCFAllocatorDefault, key, key_len);
	if (service_string == NULL || account_string == NULL || key_data == NULL) {
		if (service_string != NULL) CFRelease(service_string);
		if (account_string != NULL) CFRelease(account_string);
		if (key_data != NULL) CFRelease(key_data);
		return -1;
	}
	CFMutableDictionaryRef query = CFDictionaryCreateMutable(kCFAllocatorDefault, 0,
		&kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
	if (query == NULL) {
		CFRelease(service_string);
		CFRelease(account_string);
		CFRelease(key_data);
		return -1;
	}
	CFDictionarySetValue(query, kSecClass, kSecClassGenericPassword);
	CFDictionarySetValue(query, kSecAttrService, service_string);
	CFDictionarySetValue(query, kSecAttrAccount, account_string);
	CFDictionarySetValue(query, kSecAttrAccessible, kSecAttrAccessibleWhenUnlockedThisDeviceOnly);
	CFDictionarySetValue(query, kSecValueData, key_data);
	OSStatus status = SecItemAdd(query, NULL);
	CFRelease(query);
	CFRelease(service_string);
	CFRelease(account_string);
	CFRelease(key_data);
	if (status == errSecSuccess) return 0;
	if (status == errSecDuplicateItem) return 1;
	return -1;
}
*/
import "C"

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"
)

func main() {
	flags := flag.NewFlagSet("punaro-keychain", flag.ExitOnError)
	service := flags.String("service", "", "Keychain generic-password service")
	account := flags.String("account", "", "Keychain generic-password account")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 {
		fail("invalid arguments")
	}
	if !safeName(*service) || !safeName(*account) {
		fail("service and account must contain only letters, digits, dot, underscore, or hyphen")
	}
	serviceC := C.CString(*service)
	accountC := C.CString(*account)
	defer C.free(unsafe.Pointer(serviceC))
	defer C.free(unsafe.Pointer(accountC))
	key, err := newWrappingKey()
	if err != nil {
		fail("could not generate the macOS Keychain wrapping key")
	}
	defer zeroBytes(key)
	switch C.add_wrapping_key(serviceC, accountC, (*C.uint8_t)(unsafe.Pointer(&key[0])), C.size_t(len(key))) {
	case 0:
		fmt.Println("attachment_keychain_key_created")
	case 1:
		fmt.Println("attachment_keychain_key_exists")
	default:
		fail("could not create the macOS Keychain wrapping key")
	}
}

func newWrappingKey() ([]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return nil, err
	}
	defer zeroBytes(raw)
	encoded := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
	base64.StdEncoding.Encode(encoded, raw)
	return encoded, nil
}

func zeroBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func safeName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	return strings.IndexFunc(value, func(r rune) bool {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			return false
		default:
			return true
		}
	}) == -1
}

func fail(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "punaro-keychain:", message)
	os.Exit(2)
}
