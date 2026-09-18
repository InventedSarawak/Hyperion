package elasticsearch_test

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestElasticsearch(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Cortex Elasticsearch Adapter Suite")
}

// throwawayIndex names an index for one spec, and registers its cleanup.
//
// The name is a prefix rather than an index: New() creates "<name>-000001" and
// points the alias "<name>" at it, so what a spec holds is the alias. Every
// spec used to tear down with DELETE /<name>, which Elasticsearch refuses —
// "matches an alias, specify the corresponding concrete indices instead" — and
// since the teardown only checked for a transport error, the 400 went unseen
// and every run left its index behind. There were 240 of them.
func throwawayIndex(baseURL, prefix string) string {
	GinkgoHelper()
	name := fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano())
	DeferCleanup(func() { dropIndices(baseURL, name) })
	return name
}

// dropIndices removes every concrete index behind a name: the ones an alias
// points at, and a legacy index called exactly that. Deleting a concrete index
// takes its aliases with it.
//
// The names have to be resolved first because a cluster refuses a wildcard
// delete by default (action.destructive_requires_name), which is the whole
// reason this is two requests rather than one.
func dropIndices(baseURL, name string) {
	concrete := concreteIndices(baseURL, name)
	if concrete == "" {
		return
	}
	req, err := http.NewRequest(http.MethodDelete, baseURL+"/"+concrete, nil)
	if err != nil {
		return
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	// Loudly: a silent teardown is what let this leak for a whole milestone.
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		AddReportEntry("index teardown failed",
			fmt.Sprintf("DELETE %s -> %d: %s", concrete, resp.StatusCode, strings.TrimSpace(string(body))))
	}
}

// concreteIndices lists the real indices matching name, comma-separated for a
// single delete. Empty when there are none.
func concreteIndices(baseURL, name string) string {
	resp, err := http.Get(baseURL + "/_cat/indices/" + name + "*?h=index")
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return ""
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return ""
	}
	return strings.Join(strings.Fields(string(body)), ",")
}
