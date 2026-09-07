package graphql

import (
	"encoding/json"
	"net/http"

	"github.com/graphql-go/graphql"
)

// request is the standard GraphQL over HTTP POST body.
type request struct {
	Query         string         `json:"query"`
	OperationName string         `json:"operationName"`
	Variables     map[string]any `json:"variables"`
}

// NewHandler returns the HTTP handler serving GraphQL POST requests.
func NewHandler(schema graphql.Schema) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "graphql: use POST", http.StatusMethodNotAllowed)
			return
		}

		var req request
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "graphql: invalid request body", http.StatusBadRequest)
			return
		}

		result := graphql.Do(graphql.Params{
			Schema:         schema,
			RequestString:  req.Query,
			VariableValues: req.Variables,
			OperationName:  req.OperationName,
			Context:        r.Context(),
		})

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(result)
	})
}

// playgroundHTML is a minimal GraphiQL-style console served at /playground so
// the API can be explored from a browser without extra tooling.
const playgroundHTML = `<!doctype html>
<html>
  <head>
    <meta charset="utf-8" />
    <title>Hyperion GraphQL</title>
    <style>
      body { font-family: system-ui, sans-serif; margin: 0; padding: 24px; background: #0f172a; color: #e2e8f0; }
      h1 { font-size: 18px; margin: 0 0 16px; }
      textarea { width: 100%; height: 180px; font-family: ui-monospace, monospace; font-size: 13px;
                 padding: 12px; border-radius: 8px; border: 1px solid #334155; background: #1e293b; color: #e2e8f0; }
      button { margin-top: 12px; padding: 8px 18px; border-radius: 6px; border: 0; cursor: pointer;
               background: #38bdf8; color: #0f172a; font-weight: 600; }
      pre { margin-top: 16px; padding: 12px; border-radius: 8px; background: #1e293b; overflow: auto;
            max-height: 50vh; font-size: 13px; }
    </style>
  </head>
  <body>
    <h1>Hyperion &mdash; GraphQL</h1>
    <textarea id="q">{
  search(term: "log4j", pageSize: 5) {
    hits { score vulnerability { cveId description scores { baseScore severity } } }
    nextPageToken
  }
}</textarea>
    <br /><button onclick="run()">Run query</button>
    <pre id="out">(results appear here)</pre>
    <script>
      async function run() {
        const out = document.getElementById('out');
        out.textContent = 'running...';
        try {
          const res = await fetch('/graphql', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: document.getElementById('q').value }),
          });
          out.textContent = JSON.stringify(await res.json(), null, 2);
        } catch (err) {
          out.textContent = 'error: ' + err;
        }
      }
    </script>
  </body>
</html>`

// NewPlaygroundHandler serves the browser console.
func NewPlaygroundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(playgroundHTML))
	})
}
