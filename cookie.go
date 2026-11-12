// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import "net/http"

// newCookieFromOptions returns an http.Cookie with the options set.
func newCookieFromOptions(name, value string, options *Options) *http.Cookie {
	if options == nil {
		options = new(Options)
	}
	return &http.Cookie{
		Name:        name,
		Value:       value,
		Path:        options.Path,
		Domain:      options.Domain,
		MaxAge:      options.MaxAge,
		Secure:      options.Secure,
		HttpOnly:    options.HttpOnly,
		Partitioned: options.Partitioned,
		SameSite:    options.SameSite,
	}

}

// mergeCookieOptions combines a session's options with the store defaults.
//
// Attributes that constitute a security boundary (Secure, HttpOnly,
// Partitioned and SameSite) are never downgraded: an explicitly requested
// value wins, otherwise the store default is kept. Path and Domain are
// inherited when the session does not specify them so that deletion cookies
// keep matching the cookie they are meant to remove.
func mergeCookieOptions(defaults, options *Options) *Options {
	merged := new(Options)
	if defaults != nil {
		*merged = *defaults
	}
	if options == nil {
		return merged
	}
	if options.Path != "" {
		merged.Path = options.Path
	}
	if options.Domain != "" {
		merged.Domain = options.Domain
	}
	merged.MaxAge = options.MaxAge
	if options.Secure {
		merged.Secure = true
	}
	if options.HttpOnly {
		merged.HttpOnly = true
	}
	if options.Partitioned {
		merged.Partitioned = true
	}
	if options.SameSite != 0 {
		merged.SameSite = options.SameSite
	}
	return merged
}

// requestCookieValues returns the distinct, non-empty values of all cookies
// named name in the request, plus whether any cookie with that name was
// present at all.
//
// Unlike http.Request.Cookie(), which returns only the first matching value,
// it collects every occurrence. Browsers can legitimately send several cookies
// with the same name when they differ in path or domain, and duplicated
// Cookie headers have the same effect; the caller decides how to treat that
// ambiguity. An empty value (what browsers leave behind after deleting a
// cookie) is reported through present but never returned as a usable value.
func requestCookieValues(r *http.Request, name string) (values []string, present bool) {
	if r == nil {
		return nil, false
	}
	seen := make(map[string]struct{})
	// r.Cookies() parses every Cookie header line, while r.Cookie(name)
	// would stop at the first match.
	for _, c := range r.Cookies() {
		if c.Name != name {
			continue
		}
		present = true
		if c.Value == "" {
			continue
		}
		if _, ok := seen[c.Value]; ok {
			continue
		}
		seen[c.Value] = struct{}{}
		values = append(values, c.Value)
	}
	return values, present
}
