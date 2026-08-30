package model

// SearchHit is one scored result from the search index.
type SearchHit struct {
	Vulnerability Vulnerability
	Score         float64
}
