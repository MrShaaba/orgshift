package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/MrShaaba/orgshift/internal/snapshot"
	"github.com/MrShaaba/orgshift/internal/web"
)

func runServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ContinueOnError)
	listen := fs.String("listen", "127.0.0.1:8080", "address to listen on")
	from := fs.String("from", "", "snapshot to preload as the source")
	to := fs.String("to", "", "snapshot to preload as the target")
	withFixtures := fs.Bool("fixtures", false, "preload the fixture organizations")
	if err := fs.Parse(args); err != nil {
		return err
	}
	store := web.NewStore()
	for _, path := range []string{*from, *to} {
		if path == "" {
			continue
		}
		s, err := snapshot.Load(path)
		if err != nil {
			return err
		}
		name := s.Organization.Name
		if name == "" {
			name = strings.TrimSuffix(filepath.Base(path), ".json")
		}
		store.Add(name, s)
	}
	if *withFixtures || (*from == "" && *to == "") {
		store.LoadFixtures()
	}
	logger := log.New(os.Stderr, "orgshift ", log.LstdFlags)
	srv, err := web.New(store, logger)
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: *listen, Handler: srv.Handler(), ReadHeaderTimeout: 10 * time.Second}
	fmt.Printf("orgshift UI listening on http://%s  (loaded: %s)\n", *listen, strings.Join(store.Names(), ", "))
	return httpServer.ListenAndServe()
}
