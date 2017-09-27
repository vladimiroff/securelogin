package securelogin

import "net/url"

// Config is used for verification of a token.
type Config struct {
	publicKey  []byte
	hmacSecret []byte
	origins    map[string]struct{}
	scope      url.Values
	change     bool
	connect    bool
	hmac       bool
	expire     bool
}

// Option modifies the Configuration prior verify.
type Option func(*Config)

// NewConfig returns Config with sensible defaults and applies given options.
func NewConfig(options ...Option) Config {
	var cfg = Config{
		origins: make(map[string]struct{}),
		scope:   make(url.Values),
		expire:  true,
	}

	for _, option := range options {
		option(&cfg)
	}

	return cfg
}

// WithOrigins adds origins to the Config.
func WithOrigins(origins ...string) Option {
	return func(c *Config) {
		for _, origin := range origins {
			c.origins[origin] = struct{}{}
		}
	}
}

// WithScope adds given values to the scope. It replaces any existing values.
func WithScope(scope url.Values) Option {
	return func(c *Config) {
		for k, v := range scope {
			c.scope[k] = v
		}
	}
}

// WithPublicKey overrides PublicKey of the token.
func WithPublicKey(pubkey []byte) Option { return func(c *Config) { c.publicKey = pubkey } }

// WithSecret overrides HMACSecret of the token.
func WithSecret(secret []byte) Option { return func(c *Config) { c.hmacSecret = secret } }

// WithChange enablrd "change" mode verification.
func WithChange(c *Config) { c.change = true }

// WithConnect enables Connect request (OAuth replacement).
func WithConnect(c *Config) { c.connect = true }

// WithHMAC enables HMAC verification.
func WithHMAC(c *Config) { c.hmac = true }

// WithoutExpire disables expire checks.
func WithoutExpire(c *Config) { c.expire = false }
