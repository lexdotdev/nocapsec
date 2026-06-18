package engine

import (
	"encoding/json"
	"net/http"
)

// server adapts an Engine to the verifier HTTP API.
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

// postVerify accepts evidence, validates it, and dispatches the job.
//
// TODO: validate the body, attach policy, dispatch, return {job_id, accepted}.
func (s *server) postVerify(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "POST /verify")
}

// getVerify returns the current Report for a job, or 404 if unknown.
func (s *server) getVerify(w http.ResponseWriter, r *http.Request) {
	report, ok := s.engine.jobs.get(r.PathValue("id"))
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
		return
	}
	writeJSON(w, http.StatusOK, report)
}

// getArtifacts returns artifact references for a job.
//
// TODO: back with the artifact store.
func (s *server) getArtifacts(w http.ResponseWriter, _ *http.Request) {
	notImplemented(w, "GET /verify/{id}/artifacts")
}

func notImplemented(w http.ResponseWriter, route string) {
	writeJSON(w, http.StatusNotImplemented, map[string]string{"error": "not_implemented", "route": route})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
