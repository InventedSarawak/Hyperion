package neo4j

import driver "github.com/neo4j/neo4j-go-driver/v5/neo4j"

// Record accessors. Neo4j returns null for an OPTIONAL MATCH that found
// nothing, so every one of these coerces a missing or wrongly-typed value to
// the zero value instead of panicking on a type assertion.

func asString(record *driver.Record, key string) string {
	v, ok := record.Get(key)
	if !ok || v == nil {
		return ""
	}
	s, _ := v.(string)
	return s
}

func asInt(record *driver.Record, key string) int64 {
	v, ok := record.Get(key)
	if !ok || v == nil {
		return 0
	}
	n, _ := v.(int64)
	return n
}

func asBool(record *driver.Record, key string) bool {
	v, ok := record.Get(key)
	if !ok || v == nil {
		return false
	}
	b, _ := v.(bool)
	return b
}

func asStrings(record *driver.Record, key string) []string {
	v, ok := record.Get(key)
	if !ok || v == nil {
		return nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
