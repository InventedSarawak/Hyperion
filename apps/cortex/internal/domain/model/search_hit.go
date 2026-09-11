package model

// SearchHit is one scored result from the search index.
type SearchHit struct {
	Vulnerability Vulnerability
	Score         float64
}

// SearchSort orders results.
type SearchSort string

const (
	// SortRelevance puts the best match first. Equal scores fall back to the
	// newest record and then the CVE id, so the order is total: without that,
	// ties come back in whatever order the index stores them, and paging
	// through them can skip or repeat results.
	SortRelevance SearchSort = "relevance"
	// SortNewest puts the most recently published record first.
	SortNewest SearchSort = "newest"
)

// SearchQuery is one page of a search.
type SearchQuery struct {
	Text   string
	Sort   SearchSort
	Size   int
	Offset int
}

// SearchPage is what one query returned, and how much more there is.
type SearchPage struct {
	Hits []SearchHit
	// Total is how many records match. The index stops counting exactly at a
	// ceiling; past it Total is a floor and TotalIsLowerBound is set.
	Total             int64
	TotalIsLowerBound bool
}
