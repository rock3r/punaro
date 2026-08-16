// punaro-relay-adopt-prepare is the host-local one-shot that drops
// role/telegram-codex from a still-unnamed non-keeper and names that room.
// It opens a local SQLite relay.db and does not talk to Telegram or relay HTTP.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/rock3r/punaro/internal/relay"
)

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("punaro-relay-adopt-prepare", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var relayDB, keeper, nonKeeper, nonKeeperName string
	var yes bool
	flags.StringVar(&relayDB, "relay-db", "", "path to the local SQLite relay database")
	flags.StringVar(&keeper, "keeper", "", "conversation that keeps role/telegram-codex")
	flags.StringVar(&nonKeeper, "non-keeper", "", "still-unnamed conversation that drops role/telegram-codex")
	flags.StringVar(&nonKeeperName, "non-keeper-name", "", "display name for the non-keeper")
	flags.BoolVar(&yes, "yes", false, "required confirmation to mutate the local relay store")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 || strings.TrimSpace(relayDB) == "" || strings.TrimSpace(keeper) == "" || strings.TrimSpace(nonKeeper) == "" || strings.TrimSpace(nonKeeperName) == "" || !yes {
		_, _ = fmt.Fprintln(stderr, "usage: punaro-relay-adopt-prepare --relay-db PATH --keeper ID --non-keeper ID --non-keeper-name NAME --yes")
		return 2
	}
	store, err := relay.Open(relayDB)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, "punaro-relay-adopt-prepare failed")
		return 1
	}
	defer func() { _ = store.Close() }()
	if err := store.PrepareTelegramAdopt(relay.AdoptPrepareInput{
		KeeperID: keeper, NonKeeperID: nonKeeper, NonKeeperName: nonKeeperName, Now: time.Now().UTC(),
	}); err != nil {
		_, _ = fmt.Fprintf(stderr, "punaro-relay-adopt-prepare failed: %v\n", err)
		return 1
	}
	_, _ = fmt.Fprintln(stdout, "prepared")
	return 0
}
