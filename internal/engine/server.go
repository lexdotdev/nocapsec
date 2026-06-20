package engine

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/lexdotdev/nocapsec/internal/evidence"
	"github.com/lexdotdev/nocapsec/internal/verdict"
)

// maxBodyBytes caps request body reads (1 MiB).
const maxBodyBytes = 1 << 20

// server adapts an Engine to the HTTP API.
type server struct {
	engine *Engine
}

func newServer(e *Engine) *server {
	return &server{engine: e}
}

// handler mounts the verifier API routes.
func (s *server) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /verify", s.postVerify)
	mux.HandleFunc("GET /verify/{id}", s.getVerify)
	mux.HandleFunc("GET /verify/{id}/artifacts", s.getArtifacts)
	return mux
}

// postVerify validates evidence, then dispatches.
func (s *server) postVerify(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read_body"})
		return
	}

	// Invalid findings get 422 synchronously.
	_, parseErr := evidence.Parse(body)
	if parseErr != nil {
		reason := "parse_error"
		var ie *evidence.InvalidError
		if ok := errors.As(parseErr, &ie); ok {
			reason = ie.Reason
		}
		writeJSON(w, http.StatusUnprocessableEntity, map[string]string{
			"verdict": string(verdict.Invalid),
			"reason":  reason,
		})
		return
	}

	jobID, err := generateRandomHex()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "id_gen"})
		return
	}

	s.engine.jobs.put(jobID, verdict.NewReport("", "", "running"))

	// Background: 202 returns before pipeline finishes.
	go func(raw []byte) { //nolint:contextcheck // async pipeline outlives the HTTP request
		report, _ := s.engine.Verify(context.Background(), raw)
		s.engine.jobs.put(jobID, report)
	}(body)

	writeJSON(w, http.StatusAccepted, map[string]string{
		"job_id": jobID,
		"status": "accepted",
	})
}

// getVerify returns the current Report for a job,
// or 404 if unknown.
func (s *server) getVerify(w http.ResponseWriter, r *http.Request) {
	report, ok := s.engine.jobs.get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// getArtifacts returns artifact refs for a job.
func (s *server) getArtifacts(w http.ResponseWriter, req *http.Request) {
	report, ok := s.engine.jobs.get(req.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	refs := report.Artifacts
	if refs == nil {
		refs = verdict.ArtifactRefs{}
	}
	writeJSON(w, http.StatusOK, refs)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
