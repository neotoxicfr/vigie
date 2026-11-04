package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/neotoxicfr/vigie/internal/config"
	"github.com/neotoxicfr/vigie/internal/engine"
	"github.com/neotoxicfr/vigie/internal/mcpserver"
	"github.com/neotoxicfr/vigie/internal/scan"
	"github.com/neotoxicfr/vigie/internal/sched"
	"github.com/neotoxicfr/vigie/internal/settings"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/source/caddy"
	"github.com/neotoxicfr/vigie/internal/source/manual"
	"github.com/neotoxicfr/vigie/internal/source/nginx"
	"github.com/neotoxicfr/vigie/internal/source/npm"
	"github.com/neotoxicfr/vigie/internal/source/traefik"
	"github.com/neotoxicfr/vigie/internal/store"
	"github.com/neotoxicfr/vigie/internal/web"

	_ "time/tzdata" // image sans /usr/share/zoneinfo : TZ (ex. Europe/Paris) serait ignoré
)

var version = "dev"

const usage = `usage : vigie [-config fichier] <commande>

  serve          interface web et passages planifiés (défaut)
  scan           un passage complet, puis sortie (code 1 si échec)
  discover       inventaire des routes de toutes les sources, en JSON
  hash-password  lit un mot de passe sur l'entrée standard, écrit son hash argon2id
  healthcheck    vérifie que l'interface répond (sonde Docker)
  version        affiche la version

`

func main() {
	path := flag.String("config", envOr("VIGIE_CONFIG", "/config/config.yaml"), "fichier de configuration")
	flag.Usage = func() {
		fmt.Fprint(flag.CommandLine.Output(), usage)
		flag.PrintDefaults()
	}
	flag.Parse()
	scan.Version = version

	cmd := flag.Arg(0)
	switch cmd {
	case "version":
		fmt.Println(version)
		return
	case "hash-password":
		if err := hashPassword(); err != nil {
			log.Fatal(err)
		}
		return
	case "", "serve", "scan", "discover", "healthcheck":
	default:
		flag.Usage()
		os.Exit(2)
	}

	cfg, err := config.Load(*path)
	if err != nil {
		log.Fatal(err)
	}
	if cmd == "healthcheck" {
		if err := healthcheck(cfg.Listen); err != nil {
			log.Fatal(err)
		}
		return
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "vigie.db"))
	if err != nil {
		log.Fatal(err)
	}
	defer st.Close()
	live, err := settings.NewLive(context.Background(), st, cfg.Runtime)
	if err != nil {
		log.Fatal(err)
	}
	man := manual.New(st)
	srcs := func(r config.Runtime) []source.Source { return sources(r, man) }

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	eng := engine.New(ctx, live.Get, st, srcs)

	switch cmd {
	case "discover":
		err = discover(ctx, srcs(live.Get()))
	case "scan":
		var id int64
		if id, err = eng.RunSync(); err == nil {
			var r store.Run
			if r, err = st.GetRun(context.Background(), id); err == nil {
				fmt.Printf("passage du %s : %s, %d constats, %d écarts ouverts %s\n", r.Started.Format("02/01/2006 15:04"), r.Status, r.Findings, r.Issues, r.Note)
				if r.Status == "failed" {
					err = errors.New("passage en échec")
				}
			}
		}
	default:
		err = serve(ctx, cfg, st, man, live, srcs, eng)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func sources(cfg config.Runtime, man *manual.Manual) []source.Source {
	srcs := []source.Source{man}
	for _, t := range cfg.Sources.Traefik {
		srcs = append(srcs, traefik.New(t.Name, t.URL, t.Username, t.PasswordFile))
	}
	for _, c := range cfg.Sources.Caddy {
		srcs = append(srcs, caddy.New(c.Name, c.Location))
	}
	for _, n := range cfg.Sources.Nginx {
		srcs = append(srcs, nginx.New(n.Name, n.Location))
	}
	for _, n := range cfg.Sources.NPM {
		srcs = append(srcs, npm.New(n.Name, n.Location))
	}
	return srcs
}

func serve(ctx context.Context, cfg *config.Config, st *store.Store, man *manual.Manual, live *settings.Live,
	srcs func(config.Runtime) []source.Source, eng *engine.Engine) error {
	d := web.Deps{Cfg: cfg, Settings: live, Store: st, Manual: man, Sources: srcs, Runner: eng, Version: version,
		MCP: mcpserver.Handler(st, eng, version, func() string { return settings.Secret(live.Get().MCP.TokenFile) })}
	w, err := web.New(d)
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: w.Handler(), ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout: 30 * time.Second, WriteTimeout: 90 * time.Second, IdleTimeout: 2 * time.Minute, MaxHeaderBytes: 64 << 10}
	go sched.Loop(ctx, st, eng)
	go func() {
		<-ctx.Done()
		sctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		srv.Shutdown(sctx)
	}()
	log.Printf("vigie %s : interface sur %s", version, cfg.Listen)
	if err := srv.ListenAndServe(); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	// La base se ferme après : le passage annulé écrit ses constats et son état.
	if !eng.Wait(30*time.Second) || !w.Wait(15*time.Second) {
		log.Print("arrêt : un passage ou une analyse n'a pas fini à temps")
	}
	return nil
}

func healthcheck(listen string) error {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return err
	}
	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get("http://" + net.JoinHostPort("127.0.0.1", port) + "/static/icon.svg")
	if err != nil {
		return err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("interface : %s", resp.Status)
	}
	return nil
}

func hashPassword() error {
	fmt.Fprint(os.Stderr, "mot de passe : ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return err
	}
	pw := strings.TrimRight(line, "\r\n")
	if len(pw) < 12 {
		return errors.New("12 caractères au moins")
	}
	h, err := web.HashPassword(pw)
	if err != nil {
		return err
	}
	fmt.Println(h)
	return nil
}

// discover écrit l'inventaire en JSON ; une source en échec est signalée sans
// bloquer les autres, et le code de sortie le reflète.
func discover(ctx context.Context, srcs []source.Source) error {
	out := struct {
		Routes []source.Route    `json:"routes"`
		Errors map[string]string `json:"errors,omitempty"`
	}{Routes: []source.Route{}, Errors: map[string]string{}}
	for _, s := range srcs {
		rs, err := s.Discover(ctx)
		if err != nil {
			out.Errors[s.Name()] = err.Error()
			continue
		}
		out.Routes = append(out.Routes, rs...)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return err
	}
	if len(out.Errors) > 0 {
		return fmt.Errorf("%d source(s) en échec", len(out.Errors))
	}
	return nil
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
