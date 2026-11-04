// Package mcpserver expose vigie à un client IA par MCP : lecture des passages,
// des constats et de l'inventaire, et lancement d'un passage. Assumer un écart
// reste un geste humain, dans l'interface.
package mcpserver

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/neotoxicfr/vigie/internal/check"
	"github.com/neotoxicfr/vigie/internal/source"
	"github.com/neotoxicfr/vigie/internal/store"
)

type Runner interface {
	Start() (int64, error)
	Current() (int64, bool)
}

// LoadToken lit le jeton porteur ; trop court, il serait devinable.
func LoadToken(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("mcp.token_file : %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if len(tok) < 32 {
		return "", errors.New("mcp.token_file : jeton de 32 caractères au moins requis (ex. openssl rand -hex 32)")
	}
	return tok, nil
}

// Handler sert MCP en HTTP streamable, derrière le jeton porteur. token est relu
// à chaque requête : poser ou retirer le fichier secret active ou coupe MCP.
func Handler(st *store.Store, r Runner, version string, token func() string) http.Handler {
	srv := New(st, r, version)
	h := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, MaxRequestBodyBytes: 1 << 20})
	protected := http.NewCrossOriginProtection().Handler(h)
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		want := token()
		if len(want) < 32 {
			http.Error(w, "MCP désactivé : aucun jeton de 32 caractères au moins dans le fichier secret", http.StatusNotFound)
			return
		}
		got, ok := strings.CutPrefix(req.Header.Get("Authorization"), "Bearer ")
		if !ok || subtle.ConstantTimeCompare([]byte(got), []byte(want)) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="vigie"`)
			http.Error(w, "jeton MCP requis", http.StatusUnauthorized)
			return
		}
		protected.ServeHTTP(w, req)
	})
}

type runOut struct {
	ID       int64  `json:"id"`
	Started  string `json:"started"`
	Finished string `json:"finished,omitempty"`
	Status   string `json:"status" jsonschema:"running, ok, partial ou failed"`
	Note     string `json:"note,omitempty"`
	Findings int    `json:"findings"`
	Issues   int    `json:"open_issues" jsonschema:"constats de sévérité faible ou plus, non assumés"`
}

func toRun(r store.Run) runOut {
	o := runOut{ID: r.ID, Started: r.Started.Format(time.RFC3339), Status: r.Status, Note: r.Note, Findings: r.Findings, Issues: r.Issues}
	if !r.Finished.IsZero() {
		o.Finished = r.Finished.Format(time.RFC3339)
	}
	return o
}

type listIn struct {
	Limit int `json:"limit,omitempty" jsonschema:"nombre de passages, 20 par défaut, 200 au plus"`
}
type listOut struct {
	Runs []runOut `json:"runs"`
}

type findingsIn struct {
	RunID       int64  `json:"run_id,omitempty" jsonschema:"numéro du passage ; 0 ou absent = dernier passage terminé"`
	State       string `json:"state,omitempty" jsonschema:"vide = ouverts (nouveaux et toujours là, non assumés) ; nouveau, inchangé, résolu, assumé ou tout"`
	MinSeverity *int   `json:"min_severity,omitempty" jsonschema:"0 info, 1 faible (défaut), 2 moyen, 3 élevé"`
	Query       string `json:"query,omitempty" jsonschema:"filtre texte sur la cible, le contrôle ou le titre"`
	Limit       int    `json:"limit,omitempty" jsonschema:"200 par défaut, 2000 au plus"`
}
type findingOut struct {
	Key        string `json:"key"`
	Check      string `json:"check"`
	Target     string `json:"target"`
	Vantage    string `json:"vantage"`
	Privileged bool   `json:"privileged,omitempty"`
	Severity   string `json:"severity"`
	State      string `json:"state"`
	Title      string `json:"title"`
	Evidence   string `json:"evidence,omitempty"`
	Accepted   string `json:"accepted,omitempty" jsonschema:"raison de l'écart assumé, et son auteur"`
}
type findingsOut struct {
	Run      runOut       `json:"run"`
	Total    int          `json:"total"`
	Findings []findingOut `json:"findings"`
}

type runIn struct {
	RunID int64 `json:"run_id,omitempty" jsonschema:"numéro du passage ; 0 ou absent = dernier passage terminé"`
}
type inventoryOut struct {
	Run    runOut         `json:"run"`
	Routes []source.Route `json:"routes"`
}
type analysisOut struct {
	Run      runOut `json:"run"`
	At       string `json:"at,omitempty"`
	Provider string `json:"provider,omitempty"`
	Text     string `json:"text"`
}
type startOut struct {
	RunID          int64 `json:"run_id"`
	AlreadyRunning bool  `json:"already_running"`
}

func New(st *store.Store, r Runner, version string) *mcp.Server {
	s := mcp.NewServer(&mcp.Implementation{Name: "vigie", Title: "vigie : audit de configuration web", Version: version}, nil)
	ro := &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true}

	mcp.AddTool(s, &mcp.Tool{Name: "vigie_list_runs", Annotations: ro,
		Description: "Liste les derniers passages d'audit (du plus récent au plus ancien) avec leur statut et le nombre d'écarts ouverts."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in listIn) (*mcp.CallToolResult, listOut, error) {
			n := clamp(in.Limit, 20, 200)
			runs, err := st.Runs(ctx, n)
			out := listOut{Runs: []runOut{}}
			for _, r := range runs {
				out.Runs = append(out.Runs, toRun(r))
			}
			return nil, out, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "vigie_findings", Annotations: ro,
		Description: "Constats d'un passage comparés au précédent (état nouveau, inchangé, résolu), filtrables. « privileged » signale une mesure faite depuis un point de vue qui passe des contrôles d'accès qu'un inconnu ne passerait pas ; la vue « inconnu » est déduite de la configuration."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in findingsIn) (*mcp.CallToolResult, findingsOut, error) {
			run, err := pick(ctx, st, in.RunID)
			if err != nil {
				return nil, findingsOut{}, err
			}
			ds, err := st.Compare(ctx, run.ID)
			if err != nil {
				return nil, findingsOut{}, err
			}
			out := findingsOut{Run: toRun(run), Findings: []findingOut{}}
			limit := clamp(in.Limit, 200, 2000)
			q := strings.ToLower(strings.TrimSpace(in.Query))
			minSev := int(check.Low)
			if in.MinSeverity != nil {
				minSev = *in.MinSeverity
			}
			for _, d := range ds {
				if !d.InTab(in.State) || int(d.Severity) < minSev ||
					q != "" && !strings.Contains(strings.ToLower(d.Target+" "+d.Check+" "+d.Title), q) {
					continue
				}
				if out.Total++; len(out.Findings) >= limit {
					continue
				}
				f := findingOut{Key: d.Key(), Check: d.Check, Target: d.Target, Vantage: d.Vantage, Privileged: d.Privileged,
					Severity: d.Severity.String(), State: string(d.State), Title: d.Title, Evidence: d.Evidence}
				if d.Accepted != nil {
					f.Accepted = d.Accepted.Note + " (" + d.Accepted.Author + ")"
				}
				out.Findings = append(out.Findings, f)
			}
			return nil, out, nil
		})

	mcp.AddTool(s, &mcp.Tool{Name: "vigie_inventory", Annotations: ro,
		Description: "Routes découvertes lors d'un passage : source, hôtes, chemins, ports, chaîne de middlewares appliquée et backends."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, inventoryOut, error) {
			run, err := pick(ctx, st, in.RunID)
			if err != nil {
				return nil, inventoryOut{}, err
			}
			out := inventoryOut{Run: toRun(run), Routes: []source.Route{}}
			inv, err := st.Inventory(ctx, run.ID)
			if err == nil && len(inv) > 0 {
				err = json.Unmarshal(inv, &out.Routes)
			}
			for i := range out.Routes { // la config brute peut être volumineuse : seul le modèle commun sort
				for j := range out.Routes[i].Middlewares {
					out.Routes[i].Middlewares[j].Config = nil
				}
			}
			return nil, out, err
		})

	mcp.AddTool(s, &mcp.Tool{Name: "vigie_analysis", Annotations: ro,
		Description: "Dernière analyse IA enregistrée pour un passage (texte Markdown), si elle existe."},
		func(ctx context.Context, _ *mcp.CallToolRequest, in runIn) (*mcp.CallToolResult, analysisOut, error) {
			run, err := pick(ctx, st, in.RunID)
			if err != nil {
				return nil, analysisOut{}, err
			}
			a, err := st.GetAnalysis(ctx, run.ID)
			if errors.Is(err, sql.ErrNoRows) {
				return nil, analysisOut{Run: toRun(run), Text: "aucune analyse pour ce passage"}, nil
			}
			return nil, analysisOut{Run: toRun(run), At: a.At.Format(time.RFC3339), Provider: a.Provider, Text: a.Text}, err
		})

	no := false
	mcp.AddTool(s, &mcp.Tool{Name: "vigie_start_run",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: &no, OpenWorldHint: &no},
		Description: "Lance un passage d'audit en arrière-plan (passif et léger) et rend son numéro ; si un passage tourne déjà, rend le sien. Suivre l'avancement avec vigie_list_runs."},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, startOut, error) {
			if id, running := r.Current(); running {
				return nil, startOut{RunID: id, AlreadyRunning: true}, nil
			}
			id, err := r.Start()
			return nil, startOut{RunID: id}, err
		})
	return s
}

func clamp(v, def, max int) int {
	if v <= 0 {
		return def
	}
	if v > max {
		return max
	}
	return v
}

// pick rend le passage demandé, ou le dernier terminé (ok ou partiel).
func pick(ctx context.Context, st *store.Store, id int64) (store.Run, error) {
	if id > 0 {
		r, err := st.GetRun(ctx, id)
		if errors.Is(err, sql.ErrNoRows) {
			return r, fmt.Errorf("passage %d inconnu", id)
		}
		return r, err
	}
	runs, err := st.Runs(ctx, 50)
	if err != nil {
		return store.Run{}, err
	}
	for _, r := range runs {
		if r.Status == "ok" || r.Status == "partial" {
			return r, nil
		}
	}
	return store.Run{}, errors.New("aucun passage terminé")
}
