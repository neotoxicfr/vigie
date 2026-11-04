package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
)

type anthropicProvider struct {
	client anthropic.Client
	model  string
}

func newAnthropic(key, model, baseURL string) *anthropicProvider {
	opts := []option.RequestOption{option.WithAPIKey(key), option.WithRequestTimeout(20 * time.Minute)}
	if baseURL != "" {
		opts = append(opts, option.WithBaseURL(baseURL))
	}
	return &anthropicProvider{client: anthropic.NewClient(opts...), model: model}
}

func (p *anthropicProvider) Name() string { return "anthropic/" + p.model }

// Modèles qui acceptent le repli côté serveur « default » en cas de refus.
var fallbackModels = map[string]bool{"claude-fable-5-1": true, "claude-opus-5-5": true, "claude-opus-5": true, "claude-sonnet-5-5": true}

func (p *anthropicProvider) Analyze(ctx context.Context, system, prompt string) (string, error) {
	params := anthropic.BetaMessageNewParams{
		Model: anthropic.Model(p.model),
		// Un rapport complet à effort élevé dépasse 16 000 jetons ; le flux évite
		// le délai maximal d'une requête non diffusée.
		MaxTokens: 64000,
		// Le prompt système est fixe : en cache, il ne se paie qu'une fois par série d'analyses.
		System:       []anthropic.BetaTextBlockParam{{Text: system, CacheControl: anthropic.NewBetaCacheControlEphemeralParam()}},
		Messages:     []anthropic.BetaMessageParam{anthropic.NewBetaUserMessage(anthropic.NewBetaTextBlock(prompt))},
		OutputConfig: anthropic.BetaOutputConfigParam{Effort: anthropic.BetaOutputConfigEffortHigh},
	}
	if fallbackModels[p.model] {
		params.Betas = []anthropic.AnthropicBeta{anthropic.AnthropicBetaServerSideFallback2026_07_01}
		params.Fallbacks = anthropic.BetaFallbacksParamUnion{OfDefault: constant.ValueOf[constant.Default]()}
	}
	stream := p.client.Beta.Messages.NewStreaming(ctx, params)
	resp := anthropic.BetaMessage{}
	for stream.Next() {
		if err := resp.Accumulate(stream.Current()); err != nil {
			stream.Close()
			return "", fmt.Errorf("Anthropic : flux illisible : %w", err)
		}
	}
	if err := stream.Err(); err != nil {
		var apierr *anthropic.Error
		if errors.As(err, &apierr) {
			switch apierr.StatusCode {
			case 401, 403:
				return "", errors.New("clé API refusée par Anthropic")
			case 404:
				return "", fmt.Errorf("modèle %q inconnu chez Anthropic", p.model)
			case 429:
				return "", errors.New("limite de débit Anthropic atteinte, réessaie plus tard")
			case 529, 500, 502, 503:
				return "", errors.New("service Anthropic surchargé ou indisponible, réessaie plus tard")
			}
			return "", fmt.Errorf("Anthropic : HTTP %d", apierr.StatusCode)
		}
		return "", fmt.Errorf("Anthropic injoignable : %w", err)
	}
	if resp.StopReason == anthropic.BetaStopReasonRefusal {
		return "", errors.New("le modèle a refusé l'analyse")
	}
	var out strings.Builder
	for _, b := range resp.Content {
		if t, ok := b.AsAny().(anthropic.BetaTextBlock); ok {
			out.WriteString(t.Text)
		}
	}
	if resp.StopReason == anthropic.BetaStopReasonMaxTokens {
		out.WriteString("\n\n(réponse tronquée : limite de longueur atteinte)")
	}
	if out.Len() == 0 {
		return "", errors.New("réponse vide du modèle")
	}
	return out.String(), nil
}
