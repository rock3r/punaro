//go:build windows

// punaro-dpapi creates the one CurrentUser DPAPI-protected file used to wrap
// sender attachment file keys. It never prints or accepts the raw key.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/rock3r/punaro/internal/attachment/v3/controller"
)

func main() {
	flags := flag.NewFlagSet("punaro-dpapi", flag.ExitOnError)
	path := flags.String("file", "", "new absolute DPAPI host-key file")
	if err := flags.Parse(os.Args[1:]); err != nil || flags.NArg() != 0 || *path == "" {
		fail("invalid arguments")
	}
	if err := controller.WriteDPAPIHostKeyFile(*path); err != nil {
		fail("could not create the Windows DPAPI wrapping key")
	}
	fmt.Println("attachment_dpapi_key_created")
}

func fail(message string) {
	_, _ = fmt.Fprintln(os.Stderr, "punaro-dpapi:", message)
	os.Exit(2)
}
