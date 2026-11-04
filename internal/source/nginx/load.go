package nginx

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/tufanbarisyildirim/gonginx/config"
	"github.com/tufanbarisyildirim/gonginx/parser"
)

// Bornes contre les dossiers hostiles ou démesurés.
const (
	maxFiles      = 200
	maxFileSize   = 1 << 20
	maxTotal      = 16 << 20
	maxIncludeDep = 10
	maxExpansions = 5000 // inclusions développées, pour borner les inclusions multiples d'un même fichier
	maxBlockDepth = 64
)

// node est une directive nginx, include développé.
type node struct {
	name  string
	args  []string
	kids  []*node
	block bool
	file  string
	line  int
}

type loader struct {
	root   string // chemin réel du dossier
	cache  map[string][]*node
	total  int64
	expand int
}

// loadDir lit <dir>/nginx.conf en développant les include, tous confinés à dir.
func loadDir(dir string) ([]*node, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, fmt.Errorf("dossier %s : %w", dir, err)
	}
	l := &loader{root: root, cache: map[string][]*node{}}
	main := filepath.Join(root, "nginx.conf")
	real, err := l.check(main)
	if err != nil {
		return nil, err
	}
	raw, err := l.read(real)
	if err != nil {
		return nil, err
	}
	return l.expandNodes(raw, []string{real}, 0)
}

func (l *loader) inside(p string) bool {
	return p == l.root || strings.HasPrefix(p, l.root+string(filepath.Separator))
}

// check résout les liens symboliques de p et refuse tout ce qui sort du dossier
// ou n'est pas un fichier régulier.
func (l *loader) check(p string) (string, error) {
	real, err := filepath.EvalSymlinks(p)
	if err != nil {
		return "", fmt.Errorf("%s : %w", p, err)
	}
	if !l.inside(real) {
		return "", fmt.Errorf("%s sort du dossier (lien symbolique vers %s)", p, real)
	}
	st, err := os.Lstat(real)
	if err != nil {
		return "", err
	}
	if !st.Mode().IsRegular() {
		return "", fmt.Errorf("%s n'est pas un fichier régulier", real)
	}
	return real, nil
}

func (l *loader) read(real string) ([]*node, error) {
	if n, ok := l.cache[real]; ok {
		return n, nil
	}
	if len(l.cache) >= maxFiles {
		return nil, fmt.Errorf("plus de %d fichiers de configuration", maxFiles)
	}
	f, err := os.Open(real)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxFileSize {
		return nil, fmt.Errorf("%s : fichier > %d octets", l.rel(real), maxFileSize)
	}
	if l.total += int64(len(b)); l.total > maxTotal {
		return nil, fmt.Errorf("configuration > %d octets au total", maxTotal)
	}
	if depth(b) > maxBlockDepth {
		return nil, fmt.Errorf("%s : blocs imbriqués sur plus de %d niveaux", l.rel(real), maxBlockDepth)
	}
	nodes, err := parse(string(b), l.rel(real))
	if err != nil {
		return nil, err
	}
	l.cache[real] = nodes
	return nodes, nil
}

func (l *loader) rel(p string) string {
	if r, err := filepath.Rel(l.root, p); err == nil {
		return r
	}
	return p
}

// depth borne grossièrement l'imbrication des accolades (avant d'appeler un
// parseur récursif).
func depth(b []byte) int {
	d, max := 0, 0
	for _, c := range b {
		switch c {
		case '{':
			if d++; d > max {
				max = d
			}
		case '}':
			d--
		}
	}
	return max
}

func parse(src, name string) (nodes []*node, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("%s : analyse impossible (%v)", name, r)
		}
	}()
	c, err := parser.NewStringParser(src, parser.WithSkipValidDirectivesErr(), parser.WithSkipComments()).Parse()
	if err != nil {
		return nil, fmt.Errorf("%s : %w", name, err)
	}
	return convert(c.Block.GetDirectives(), name), nil
}

func convert(ds []config.IDirective, file string) []*node {
	var out []*node
	for _, d := range ds {
		n := &node{name: d.GetName(), file: file, line: d.GetLine()}
		for _, p := range d.GetParameters() {
			n.args = append(n.args, unquote(p.GetValue()))
		}
		if b := d.GetBlock(); b != nil && !isNil(b) {
			n.block = true
			n.kids = convert(b.GetDirectives(), file)
		}
		out = append(out, n)
	}
	return out
}

func isNil(b config.IBlock) bool {
	blk, ok := b.(*config.Block)
	return ok && blk == nil
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}

func (l *loader) expandNodes(in []*node, stack []string, dep int) ([]*node, error) {
	var out []*node
	for _, n := range in {
		if n.name != "include" {
			c := *n
			if n.block {
				kids, err := l.expandNodes(n.kids, stack, dep)
				if err != nil {
					return nil, err
				}
				c.kids = kids
			}
			out = append(out, &c)
			continue
		}
		if len(n.args) != 1 {
			return nil, fmt.Errorf("%s:%d : include attend un argument", n.file, n.line)
		}
		if dep+1 > maxIncludeDep {
			return nil, fmt.Errorf("%s:%d : include imbriqués sur plus de %d niveaux", n.file, n.line, maxIncludeDep)
		}
		files, err := l.resolve(n.args[0])
		if err != nil {
			return nil, fmt.Errorf("%s:%d : %w", n.file, n.line, err)
		}
		for _, real := range files {
			if l.expand++; l.expand > maxExpansions {
				return nil, fmt.Errorf("plus de %d inclusions développées", maxExpansions)
			}
			for _, s := range stack {
				if s == real {
					return nil, fmt.Errorf("%s:%d : boucle d'include sur %s", n.file, n.line, l.rel(real))
				}
			}
			raw, err := l.read(real)
			if err != nil {
				return nil, err
			}
			sub, err := l.expandNodes(raw, append(append([]string{}, stack...), real), dep+1)
			if err != nil {
				return nil, err
			}
			out = append(out, sub...)
		}
	}
	return out, nil
}

// resolve donne les fichiers réels visés par un include, tous dans le dossier.
// Les chemins relatifs partent du dossier ; un chemin absolu hors dossier n'est
// accepté que sous /etc/nginx/ (réécrit vers le dossier), comme dans l'image officielle.
func (l *loader) resolve(pat string) ([]string, error) {
	if strings.ContainsAny(pat, "$") {
		return nil, fmt.Errorf("include avec variable refusé : %s", pat)
	}
	p := pat
	if filepath.IsAbs(p) {
		switch c := filepath.Clean(p); {
		case l.inside(c):
			p = c
		case strings.HasPrefix(c, "/etc/nginx/"):
			p = filepath.Join(l.root, strings.TrimPrefix(c, "/etc/nginx/"))
		default:
			return nil, fmt.Errorf("include hors du dossier : %s", pat)
		}
	} else {
		p = filepath.Join(l.root, p) // Join nettoie : « ../ » remonte lexicalement
	}
	if !l.inside(p) {
		return nil, fmt.Errorf("include hors du dossier : %s", pat)
	}
	glob := strings.ContainsAny(p, "*?[")
	matches, err := filepath.Glob(p)
	if err != nil {
		return nil, fmt.Errorf("motif d'include invalide %s : %w", pat, err)
	}
	if len(matches) == 0 && !glob {
		return nil, fmt.Errorf("include introuvable : %s", pat)
	}
	var out []string
	for _, m := range matches {
		if glob && strings.HasPrefix(filepath.Base(m), ".") {
			continue // comme glob(3) : les fichiers cachés ne sont pas pris par un joker
		}
		real, err := l.check(m)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return nil, err
		}
		out = append(out, real)
	}
	return out, nil
}
