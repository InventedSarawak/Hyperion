package config

import (
	"time"

	"github.com/inventedsarawak/hyperion/apps/siphon/internal/domain/valueobject"
)

// Cadence is how often one source is polled and how far back its first poll
// reaches when it has no stored watermark.
type Cadence struct {
	Interval time.Duration
	Lookback time.Duration
}

// defaultCadence is what each feed actually needs, rather than one setting for
// all ten.
//
// The rates differ by orders of magnitude. NVD, MITRE and GSD publish hundreds
// of records a day and are worth asking every few minutes over a short window.
// Exploit-DB, OSINT and the package feeds publish a handful a *week*: at a
// two-hour window they return nothing essentially always, which reads as a
// broken adapter and is not one. They are asked rarely, over a window long
// enough to contain something.
var defaultCadence = map[valueobject.SourceKind]Cadence{
	valueobject.SourceKindNVD:    {Interval: 10 * time.Minute, Lookback: 2 * time.Hour},
	valueobject.SourceKindMITRE:  {Interval: 10 * time.Minute, Lookback: 2 * time.Hour},
	valueobject.SourceKindGSD:    {Interval: 30 * time.Minute, Lookback: 24 * time.Hour},
	valueobject.SourceKindShodan: {Interval: 30 * time.Minute, Lookback: 24 * time.Hour},
	// Only reviewed GitHub advisories carry affected-package data, and about
	// one appears every six hours — a short window finds none of them.
	valueobject.SourceKindGitHubAdvisory: {Interval: 15 * time.Minute, Lookback: 12 * time.Hour},
	// A catalog that changes roughly daily.
	valueobject.SourceKindCISAKEV:        {Interval: time.Hour, Lookback: 48 * time.Hour},
	valueobject.SourceKindVendorAdvisory: {Interval: time.Hour, Lookback: 48 * time.Hour},
	// A few records a week each: a 10-minute poll over 2 hours was asking ten
	// times an hour for something that changes on Tuesdays.
	valueobject.SourceKindExploitDB:   {Interval: 6 * time.Hour, Lookback: 14 * 24 * time.Hour},
	valueobject.SourceKindOSINT:       {Interval: 2 * time.Hour, Lookback: 7 * 24 * time.Hour},
	valueobject.SourceKindPackageFeed: {Interval: 6 * time.Hour, Lookback: 14 * 24 * time.Hour},
}

// cadenceEnvPrefix maps a source onto the prefix its other settings already
// use, so SIPHON_NVD_INTERVAL sits beside SIPHON_NVD_API_KEY rather than
// inventing a second naming scheme for the same feed.
var cadenceEnvPrefix = map[valueobject.SourceKind]string{
	valueobject.SourceKindNVD:            "NVD",
	valueobject.SourceKindGitHubAdvisory: "GITHUB",
	valueobject.SourceKindCISAKEV:        "CISA_KEV",
	valueobject.SourceKindExploitDB:      "EXPLOITDB",
	valueobject.SourceKindMITRE:          "MITRE",
	valueobject.SourceKindVendorAdvisory: "VENDOR",
	valueobject.SourceKindOSINT:          "OSINT",
	valueobject.SourceKindPackageFeed:    "PACKAGE_FEEDS",
	valueobject.SourceKindShodan:         "SHODAN",
	valueobject.SourceKindGSD:            "GSD",
}

// CadenceFor resolves one source's polling cadence.
//
// SIPHON_<SOURCE>_INTERVAL and SIPHON_<SOURCE>_LOOKBACK override the default
// for that feed alone. The old global SIPHON_POLL_INTERVAL and SIPHON_LOOKBACK
// still work and override every source at once, for the times when you want
// one answer — a first run, or a deliberate catch-up — without editing ten
// settings.
func (c Config) CadenceFor(kind valueobject.SourceKind) (interval, lookback time.Duration) {
	base, ok := defaultCadence[kind]
	if !ok {
		base = Cadence{Interval: 10 * time.Minute, Lookback: 2 * time.Hour}
	}

	if c.loader == nil {
		return base.Interval, base.Lookback
	}

	// A global override wins over the per-source default, and a per-source
	// setting wins over both. Only an explicitly set global counts: the
	// defaults of SIPHON_POLL_INTERVAL and SIPHON_LOOKBACK must not quietly
	// flatten every feed back to one cadence.
	if c.loader.Has("POLL_INTERVAL") {
		base.Interval = c.PollInterval
	}
	if c.loader.Has("LOOKBACK") {
		base.Lookback = c.Lookback
	}

	prefix, ok := cadenceEnvPrefix[kind]
	if !ok {
		return base.Interval, base.Lookback
	}
	return c.loader.Duration(prefix+"_INTERVAL", base.Interval),
		c.loader.Duration(prefix+"_LOOKBACK", base.Lookback)
}

// MinInterval is the shortest cadence across every source, which is how often
// the scheduler has to wake up for the most frequent one to be on time.
func (c Config) MinInterval(kinds []valueobject.SourceKind) time.Duration {
	shortest := time.Duration(0)
	for _, k := range kinds {
		interval, _ := c.CadenceFor(k)
		if shortest == 0 || interval < shortest {
			shortest = interval
		}
	}
	if shortest <= 0 {
		return time.Minute
	}
	return shortest
}
