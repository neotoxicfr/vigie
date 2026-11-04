// Package ai envoie un passage à un modèle de langage pour en tirer priorités
// et correctifs. Rien ne part sans action explicite de l'utilisateur.
package ai

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

type Provider interface {
	Name() string // ex. "anthropic/claude-opus-5-5"
	Analyze(ctx context.Context, system, prompt string) (string, error)
}

// Config : fournisseur choisi dans le fichier de configuration.
type Config struct {
	Provider   string `yaml:"provider" json:"provider"`         // "anthropic" ou "openai" (toute API compatible : Ollama, LM Studio, OpenRouter…)
	Model      string `yaml:"model" json:"model"`               // défaut anthropic : claude-opus-5-5
	BaseURL    string `yaml:"base_url" json:"base_url"`         // openai : ex. http://ollama:11434/v1
	APIKeyFile string `yaml:"api_key_file" json:"api_key_file"` // clé dans un fichier, jamais dans la config
	// Context : choix déjà tranchés par l'administrateur, donnés à chaque analyse
	// pour que le modèle ne propose pas de correctif qui les contredit.
	Context string `yaml:"context" json:"context"`
}

const DefaultAnthropicModel = "claude-opus-5-5"

const maxContext = 8000

func (c Config) Validate() error {
	if len(c.Context) > maxContext {
		return fmt.Errorf("ai.context : %d caractères au plus", maxContext)
	}
	switch c.Provider {
	case "":
		return nil
	case "anthropic":
		if c.APIKeyFile == "" {
			return errors.New("ai.api_key_file requis pour anthropic")
		}
	case "openai":
		if c.BaseURL == "" || c.Model == "" {
			return errors.New("ai.base_url et ai.model requis pour un fournisseur compatible OpenAI")
		}
	default:
		return fmt.Errorf("ai.provider %q inconnu (anthropic ou openai)", c.Provider)
	}
	return nil
}

// New rend nil sans fournisseur configuré : l'analyse est alors désactivée.
func New(c Config) (Provider, error) {
	if c.Provider == "" {
		return nil, nil
	}
	key := ""
	if c.APIKeyFile != "" {
		b, err := os.ReadFile(c.APIKeyFile)
		if err != nil {
			return nil, fmt.Errorf("ai.api_key_file : %w", err)
		}
		key = strings.TrimSpace(string(b))
	}
	if c.Provider == "anthropic" {
		if key == "" {
			return nil, fmt.Errorf("clé Anthropic absente (%s vide)", c.APIKeyFile)
		}
		m := c.Model
		if m == "" {
			m = DefaultAnthropicModel
		}
		return newAnthropic(key, m, c.BaseURL), nil
	}
	return &openAI{base: strings.TrimRight(c.BaseURL, "/"), key: key, model: c.Model}, nil
}
