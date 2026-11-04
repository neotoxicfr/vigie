package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// openAI parle le protocole /chat/completions, que suivent Ollama, LM Studio,
// vLLM, OpenRouter, Mistral… : une IA locale garde les données sur le réseau.
type openAI struct {
	base, key, model string
}

func (p *openAI) Name() string { return "openai/" + p.model }

var httpClient = &http.Client{Timeout: 10 * time.Minute} // un modèle local peut être lent

func (p *openAI) Analyze(ctx context.Context, system, prompt string) (string, error) {
	body, _ := json.Marshal(map[string]any{
		"model": p.model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": prompt},
		},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if p.key != "" {
		req.Header.Set("Authorization", "Bearer "+p.key)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("fournisseur injoignable : %w", err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("fournisseur : HTTP %d", resp.StatusCode)
	}
	var r struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return "", fmt.Errorf("réponse illisible : %w", err)
	}
	if len(r.Choices) == 0 || r.Choices[0].Message.Content == "" {
		return "", errors.New("réponse vide du modèle")
	}
	out := r.Choices[0].Message.Content
	if r.Choices[0].FinishReason == "length" {
		out += "\n\n(réponse tronquée : limite de longueur atteinte)"
	}
	return out, nil
}
