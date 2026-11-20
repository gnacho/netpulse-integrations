package keenetic

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gnacho/netpulse-integrations/keenetic/internal/translate"
)

// FleetConfig is the JSON configuration of the fleet shape: one process
// polling every unit of one Keenetic installation and pushing one signed
// payload per unit. Lives in a chmod 600 file (it carries the agent tokens
// and the read-only account password) and never in a repository.
//
//	{
//	  "server":   "http://192.168.1.2:3000",
//	  "interval": "60s",
//	  "host":     "192.168.1.1",
//	  "user":     "netpulse-reader",
//	  "password": "...",
//	  "units": [
//	    {"slug": "keenetic-main", "token": "..."},
//	    {"slug": "keenetic-ap1",  "token": "...", "mac": "50:ff:20:..."}
//	  ]
//	}
type FleetConfig struct {
	// Server is the NetPulse base URL. Required.
	Server string `json:"server"`
	// Interval is the push cadence (Go duration). Default 60s.
	IntervalRaw string `json:"interval,omitempty"`

	// Keenetic connection (the controller, or a standalone unit).
	Host        string `json:"host"`
	User        string `json:"user"`
	Password    string `json:"password"`
	TimeoutRaw  string `json:"timeout,omitempty"`
	InsecureTLS bool   `json:"insecure_tls,omitempty"`

	// TLS to the NetPulse server (HTTPS): a CA file or an SPKI pin, never
	// both. Plain HTTP needs neither.
	CAFile   string `json:"ca_file,omitempty"`
	ServerFP string `json:"server_fp,omitempty"`

	// Trust of the router's own certificate (https:// units): an SPKI pin
	// of the unit certificate. InsecureTLS is the explicit opt-out; setting
	// both is a configuration error.
	CertFP string `json:"cert_fp,omitempty"`

	Units []Unit `json:"units"`

	// parsed
	Interval time.Duration
	Timeout  time.Duration
}

// LoadFleetConfig reads and validates the fleet configuration file.
func LoadFleetConfig(path string) (*FleetConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read fleet config: %w", err)
	}
	var cfg FleetConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, fmt.Errorf("parse fleet config %s: %w", path, err)
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("fleet config %s: %w", path, err)
	}
	return &cfg, nil
}

func (c *FleetConfig) validate() error {
	c.Server = strings.TrimSpace(c.Server)
	if c.Server == "" {
		return errFleet("server is required")
	}
	if c.Host == "" {
		return errFleet("host is required")
	}
	if c.User == "" || c.Password == "" {
		return errFleet("user and password are required")
	}
	if len(c.Units) == 0 {
		return errNoUnits
	}
	seen := map[string]bool{}
	for i := range c.Units {
		u := &c.Units[i]
		u.Slug = strings.TrimSpace(u.Slug)
		u.Token = strings.TrimSpace(u.Token)
		u.MAC = strings.TrimSpace(u.MAC)
		if u.Slug == "" {
			return errBadUnit{unit: i, why: "slug is required"}
		}
		if u.Token == "" {
			return errBadUnit{unit: i, why: "token is required"}
		}
		if u.MAC != "" {
			normalized := translate.NormalizeMAC(u.MAC)
			if normalized == "" {
				return errBadUnit{unit: i, why: "invalid MAC " + u.MAC}
			}
			u.MAC = normalized
		}
		if seen[u.Slug] {
			return errBadUnit{unit: i, why: "duplicate slug " + u.Slug}
		}
		seen[u.Slug] = true
	}
	interval := 60 * time.Second
	if c.IntervalRaw != "" {
		d, err := time.ParseDuration(c.IntervalRaw)
		if err != nil || d <= 0 {
			return errFleet("invalid interval " + c.IntervalRaw)
		}
		interval = d
	}
	c.Interval = interval
	if c.CertFP != "" && c.InsecureTLS {
		return errFleet("cert_fp and insecure_tls are mutually exclusive: pick one way to trust the unit certificate")
	}
	if c.TimeoutRaw != "" {
		d, err := time.ParseDuration(c.TimeoutRaw)
		if err != nil || d <= 0 {
			return errFleet("invalid timeout " + c.TimeoutRaw)
		}
		c.Timeout = d
	}
	return nil
}
