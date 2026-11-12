// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/gorilla/securecookie"
)

const (
	// File name prefix for session files.
	sessionFilePrefix = "session_"
)

// ErrInvalidSession is returned when a request cookie could not be
// authenticated, or when several distinct cookies matched the session name
// and it is impossible to tell which one is authoritative.
//
// The error deliberately does not include the submitted cookie value or any
// decoded content, so it is safe to log or return to the caller.
var ErrInvalidSession = errors.New("sessions: invalid session cookie")

// invalidCookieError reports a rejected session cookie without echoing its
// contents. The underlying cause is kept for debugging via Unwrap().
type invalidCookieError struct {
	name  string
	cause error
}

func (e *invalidCookieError) Error() string {
	return fmt.Sprintf("sessions: invalid session cookie %q", e.name)
}

func (e *invalidCookieError) Unwrap() error { return e.cause }

// Is makes errors.Is(err, ErrInvalidSession) report true.
func (e *invalidCookieError) Is(target error) bool { return target == ErrInvalidSession }

// decodeSessionCookie decodes the candidate values found for a cookie name.
//
// Several values may be present because a browser can send more than one
// cookie with the same name (differing by path or domain) or because of
// duplicate Cookie headers. Every candidate is decoded with a fresh
// destination so that a failed attempt cannot leave partially decoded data
// behind. A candidate is accepted only if its signature and timestamp
// validate; tampered, truncated or otherwise malformed values are ignored as
// long as another candidate is authentic.
//
// If no candidate validates, ErrInvalidSession is returned. If more than one
// distinct candidate validates, the request is ambiguous and is rejected as
// well; silently picking one could let an attacker influence which session is
// used.
func decodeSessionCookie[T any](name string, values []string, codecs []securecookie.Codec) (T, error) {
	var (
		zero    T
		decoded T
		found   bool
		cause   error
	)
	for _, value := range values {
		for _, codec := range codecs {
			dst := new(T)
			// Decode codec by codec instead of securecookie.DecodeMulti so
			// that each attempt gets a clean destination.
			err := codec.Decode(name, value, dst)
			if err != nil {
				if cause == nil {
					cause = err
				}
				continue
			}
			if !found {
				decoded, found = *dst, true
			} else if !reflect.DeepEqual(decoded, *dst) {
				// Two different authentic cookies for the same name: do not
				// guess which one the client meant.
				return zero, &invalidCookieError{name: name}
			}
			// The value was authenticated; do not try the remaining codecs
			// on it (they would decode the same payload).
			break
		}
	}
	if !found {
		return zero, &invalidCookieError{name: name, cause: cause}
	}
	return decoded, nil
}

// encodeSessionCookie encodes a session using only the current (first) codec.
//
// Older codecs are present solely to validate cookies issued before a key
// rotation. Falling back to them for signing would silently keep using a
// retired key, so encoding never walks the codec list.
func encodeSessionCookie(name string, value interface{}, codecs []securecookie.Codec) (string, error) {
	if len(codecs) == 0 {
		return "", errors.New("sessions: no codecs configured")
	}
	return codecs[0].Encode(name, value)
}

// Store is an interface for custom session stores.
//
// See CookieStore and FilesystemStore for examples.
type Store interface {
	// Get should return a cached session.
	Get(r *http.Request, name string) (*Session, error)

	// New should create and return a new session.
	//
	// Note that New should never return a nil session, even in the case of
	// an error if using the Registry infrastructure to cache the session.
	New(r *http.Request, name string) (*Session, error)

	// Save should persist session to the underlying store implementation.
	Save(r *http.Request, w http.ResponseWriter, s *Session) error
}

// CookieStore ----------------------------------------------------------------

// NewCookieStore returns a new CookieStore.
//
// Keys are defined in pairs to allow key rotation, but the common case is
// to set a single authentication key and optionally an encryption key.
//
// The first key in a pair is used for authentication and the second for
// encryption. The encryption key can be set to nil or omitted in the last
// pair, but the authentication key is required in all pairs.
//
// When several key pairs are provided, only the first pair is used to encode
// cookies. The remaining pairs are used to validate (and decrypt) cookies
// issued before a key rotation. This means a retired key can still be read,
// but it can never be used to sign a new session.
//
// It is recommended to use an authentication key with 32 or 64 bytes.
// The encryption key, if set, must be either 16, 24, or 32 bytes to select
// AES-128, AES-192, or AES-256 modes.
func NewCookieStore(keyPairs ...[]byte) *CookieStore {
	cs := &CookieStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &Options{
			Path:     "/",
			MaxAge:   86400 * 30,
			SameSite: http.SameSiteNoneMode,
			Secure:   true,
		},
	}

	cs.MaxAge(cs.Options.MaxAge)
	return cs
}

// CookieStore stores sessions using secure cookies.
type CookieStore struct {
	Codecs  []securecookie.Codec
	Options *Options // default configuration
}

// Get returns a session for the given name after adding it to the registry.
//
// It returns a new session if the sessions doesn't exist. Access IsNew on
// the session to check if it is an existing session or a new one.
//
// It returns a new session and an error if the session exists but could
// not be decoded.
func (s *CookieStore) Get(r *http.Request, name string) (*Session, error) {
	return GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// The difference between New() and Get() is that calling New() twice will
// decode the session data twice, while Get() registers and reuses the same
// decoded session after the first call.
//
// A cookie that fails authentication, that exceeds the configured size limit,
// or that appears several times with different valid values is reported as
// ErrInvalidSession. The returned session is always new in that case and
// contains no data from the rejected cookie.
func (s *CookieStore) New(r *http.Request, name string) (*Session, error) {
	session := NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	values, present := requestCookieValues(r, name)
	if !present || len(values) == 0 {
		// No cookie, or only an empty (deleted) one: start a fresh session.
		return session, nil
	}
	decoded, err := decodeSessionCookie[map[interface{}]interface{}](name, values, s.Codecs)
	if err != nil {
		return session, err
	}
	if decoded != nil {
		session.Values = decoded
	}
	session.IsNew = false
	return session, nil
}

// Save adds a single session to the response.
//
// When the session's MaxAge is negative the cookie is expired immediately and
// no session data is written, so that a logout cannot leave an authentic
// cookie behind. Cookies are always encoded with the current key and keep the
// store's security attributes (Secure, HttpOnly, SameSite and Partitioned).
func (s *CookieStore) Save(r *http.Request, w http.ResponseWriter,
	session *Session) error {
	opts := mergeCookieOptions(s.Options, session.Options)
	if opts.MaxAge < 0 {
		http.SetCookie(w, NewCookie(session.Name(), "", opts))
		return nil
	}
	encoded, err := encodeSessionCookie(session.Name(), session.Values, s.Codecs)
	if err != nil {
		return err
	}
	http.SetCookie(w, NewCookie(session.Name(), encoded, opts))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *CookieStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// MaxLength restricts the maximum length of cookies to l.
// If l is 0 there is no limit to the size of a cookie, use with caution.
// The default for a new CookieStore is 4096, which matches the size browsers
// accept for a single cookie.
func (s *CookieStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// FilesystemStore ------------------------------------------------------------

var fileMutex sync.RWMutex

// NewFilesystemStore returns a new FilesystemStore.
//
// The path argument is the directory where sessions will be saved. If empty
// it will use os.TempDir().
//
// See NewCookieStore() for a description of the other parameters.
func NewFilesystemStore(path string, keyPairs ...[]byte) *FilesystemStore {
	if path == "" {
		path = os.TempDir()
	}
	fs := &FilesystemStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		path: path,
	}

	fs.MaxAge(fs.Options.MaxAge)
	return fs
}

// FilesystemStore stores sessions in the filesystem.
//
// It also serves as a reference for custom stores.
//
// This store is still experimental and not well tested. Feedback is welcome.
type FilesystemStore struct {
	Codecs  []securecookie.Codec
	Options *Options // default configuration
	path    string
}

// MaxLength restricts the maximum length of new sessions to l.
// If l is 0 there is no limit to the size of a session, use with caution.
// The default for a new FilesystemStore is 4096.
func (s *FilesystemStore) MaxLength(l int) {
	for _, c := range s.Codecs {
		if codec, ok := c.(*securecookie.SecureCookie); ok {
			codec.MaxLength(l)
		}
	}
}

// Get returns a session for the given name after adding it to the registry.
//
// See CookieStore.Get().
func (s *FilesystemStore) Get(r *http.Request, name string) (*Session, error) {
	return GetRegistry(r).Get(s, name)
}

// New returns a session for the given name without adding it to the registry.
//
// See CookieStore.New().
func (s *FilesystemStore) New(r *http.Request, name string) (*Session, error) {
	session := NewSession(s, name)
	opts := *s.Options
	session.Options = &opts
	session.IsNew = true
	values, present := requestCookieValues(r, name)
	if !present || len(values) == 0 {
		return session, nil
	}
	decoded, err := decodeSessionCookie[string](name, values, s.Codecs)
	if err != nil {
		return session, err
	}
	session.ID = decoded
	if err = s.load(session); err != nil {
		if os.IsNotExist(err) {
			// The cookie is authentic but the session file is gone; treat
			// it as a new session rather than surfacing the raw path.
			session.ID = ""
			return session, nil
		}
		var invalid *invalidCookieError
		if errors.As(err, &invalid) {
			// The stored payload did not authenticate; load already
			// reported it without echoing its content.
			session.ID = ""
			return session, err
		}
		return session, &invalidCookieError{name: name, cause: err}
	}
	session.IsNew = false
	return session, nil
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// Save adds a single session to the response.
//
// If the Options.MaxAge of the session is <= 0 then the session file will be
// deleted from the store path. With this process it enforces the properly
// session cookie handling so no need to trust in the cookie management in the
// web browser.
//
// The cookie is always signed with the current key and keeps the store's
// security attributes (Secure, HttpOnly, SameSite and Partitioned).
func (s *FilesystemStore) Save(r *http.Request, w http.ResponseWriter,
	session *Session) error {
	opts := mergeCookieOptions(s.Options, session.Options)
	// Delete if max-age is <= 0
	if opts.MaxAge <= 0 {
		if err := s.erase(session); err != nil && !os.IsNotExist(err) {
			return err
		}
		http.SetCookie(w, NewCookie(session.Name(), "", opts))
		return nil
	}

	if session.ID == "" {
		// Because the ID is used in the filename, encode it to
		// use alphanumeric characters only.
		session.ID = base32RawStdEncoding.EncodeToString(
			securecookie.GenerateRandomKey(32))
	}
	if err := s.save(session); err != nil {
		return err
	}
	encoded, err := encodeSessionCookie(session.Name(), session.ID, s.Codecs)
	if err != nil {
		return err
	}
	http.SetCookie(w, NewCookie(session.Name(), encoded, opts))
	return nil
}

// MaxAge sets the maximum age for the store and the underlying cookie
// implementation. Individual sessions can be deleted by setting Options.MaxAge
// = -1 for that session.
func (s *FilesystemStore) MaxAge(age int) {
	s.Options.MaxAge = age

	// Set the maxAge for each securecookie instance.
	for _, codec := range s.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

// save writes encoded session.Values to a file.
func (s *FilesystemStore) save(session *Session) error {
	encoded, err := encodeSessionCookie(session.Name(), session.Values, s.Codecs)
	if err != nil {
		return err
	}
	filename := filepath.Join(s.path, sessionFilePrefix+filepath.Base(session.ID))
	fileMutex.Lock()
	defer fileMutex.Unlock()
	return os.WriteFile(filename, []byte(encoded), 0600)
}

// load reads a file and decodes its content into session.Values.
func (s *FilesystemStore) load(session *Session) error {
	filename := filepath.Join(s.path, sessionFilePrefix+filepath.Base(session.ID))
	fileMutex.RLock()
	defer fileMutex.RUnlock()
	fdata, err := os.ReadFile(filepath.Clean(filename))
	if err != nil {
		return err
	}
	values, err := decodeSessionCookie[map[interface{}]interface{}](
		session.Name(), []string{string(fdata)}, s.Codecs)
	if err != nil {
		return err
	}
	if values != nil {
		session.Values = values
	}
	return nil
}

// delete session file
func (s *FilesystemStore) erase(session *Session) error {
	filename := filepath.Join(s.path, sessionFilePrefix+filepath.Base(session.ID))

	fileMutex.Lock()
	defer fileMutex.Unlock()

	err := os.Remove(filename)
	return err
}
