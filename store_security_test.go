// Copyright 2012 The Gorilla Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package sessions

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gorilla/securecookie"
)

// Test key material shared by the security tests. These keys are generated
// locally by the tests and are never used by production code.
var (
	oldHashKey  = []byte("old-authentication-key-0123456789")
	oldBlockKey = []byte("old-encryption-key-0123456789abc")
	newHashKey  = []byte("new-authentication-key-0123456789")
	newBlockKey = []byte("new-encryption-key-0123456789abc")
)

// setCookie is a parsed Set-Cookie value produced by a store.
type setCookie struct {
	name     string
	value    string
	path     string
	domain   string
	maxAge   int
	secure   bool
	httpOnly bool
	sameSite http.SameSite
}

// saveSession saves the session and returns the Set-Cookie value from the
// response.
func saveSession(t *testing.T, store Store, session *Session) setCookie {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	return parseSetCookie(t, rec)
}

// parseSetCookie returns the single Set-Cookie value written to rec.
func parseSetCookie(t *testing.T, rec *httptest.ResponseRecorder) setCookie {
	t.Helper()
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("expected exactly one Set-Cookie, got %d", len(cookies))
	}
	c := cookies[0]
	return setCookie{
		name:     c.Name,
		value:    c.Value,
		path:     c.Path,
		domain:   c.Domain,
		maxAge:   c.MaxAge,
		secure:   c.Secure,
		httpOnly: c.HttpOnly,
		sameSite: c.SameSite,
	}
}

// newEncodedSession produces a cookie value for name/values signed with
// store, without going through Save so that specific keys can be used.
func newEncodedSession(t *testing.T, store *CookieStore, name string, values map[interface{}]interface{}) string {
	t.Helper()
	encoded, err := encodeSessionCookie(name, values, store.Codecs)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return encoded
}

// requestWithCookies builds a request whose Cookie headers contain the given
// raw cookie strings, one header line each. Separate lines exercise the case
// where a browser or proxy splits duplicate cookies across header lines.
func requestWithCookies(lines ...string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	for _, line := range lines {
		req.Header.Add("Cookie", line)
	}
	return req
}

// assertInvalid asserts that err is (or wraps) ErrInvalidSession and that the
// session contains no data from the rejected cookie.
func assertInvalid(t *testing.T, session *Session, err error, secret string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error, got nil")
	}
	if !errors.Is(err, ErrInvalidSession) {
		t.Fatalf("expected ErrInvalidSession, got %v", err)
	}
	if session == nil {
		t.Fatalf("expected a non-nil session")
	}
	if !session.IsNew {
		t.Fatalf("rejected cookie must not mark the session as existing")
	}
	if len(session.Values) != 0 {
		t.Fatalf("rejected cookie leaked values: %v", session.Values)
	}
	if secret != "" {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks session content: %q", err.Error())
		}
		for k, v := range session.Values {
			if fmt.Sprint(k) == secret || fmt.Sprint(v) == secret {
				t.Fatalf("rejected cookie leaked %q", secret)
			}
		}
	}
}

func TestKeyRotationOnlyCurrentKeySigns(t *testing.T) {
	old := NewCookieStore(oldHashKey, oldBlockKey)

	// A cookie issued before the rotation, signed with the old key.
	values := map[interface{}]interface{}{"user": "alice"}
	oldValue := newEncodedSession(t, old, "session", values)

	// The rotated store: new key first, old key retained for verification.
	rotated := NewCookieStore(newHashKey, newBlockKey, oldHashKey, oldBlockKey)

	// The old cookie must still authenticate.
	req := requestWithCookies("session=" + oldValue)
	session, err := rotated.New(req, "session")
	if err != nil {
		t.Fatalf("rotated store failed to verify old cookie: %v", err)
	}
	if session.IsNew {
		t.Fatalf("old cookie should produce an existing session")
	}
	if session.Values["user"] != "alice" {
		t.Fatalf("bad value: %v", session.Values["user"])
	}

	// Re-saving must sign with the current key only.
	saved := saveSession(t, rotated, session)
	if saved.value == oldValue {
		t.Fatalf("Save reused the old cookie instead of re-signing")
	}

	rotatedReq := requestWithCookies("session=" + saved.value)
	if _, err := rotated.New(rotatedReq, "session"); err != nil {
		t.Fatalf("rotated store failed to verify its own cookie: %v", err)
	}

	// A store that only knows the new key accepts the re-signed cookie.
	newOnly := NewCookieStore(newHashKey, newBlockKey)
	reqNew := requestWithCookies("session=" + saved.value)
	sessNew, err := newOnly.New(reqNew, "session")
	if err != nil {
		t.Fatalf("new-key-only store rejected re-signed cookie: %v", err)
	}
	if sessNew.IsNew || sessNew.Values["user"] != "alice" {
		t.Fatalf("unexpected session from re-signed cookie: new=%v values=%v",
			sessNew.IsNew, sessNew.Values)
	}

	// A store that only knows the old key must reject the re-signed cookie:
	// the retired key can verify but never sign.
	oldOnly := NewCookieStore(oldHashKey, oldBlockKey)
	reqOld := requestWithCookies("session=" + saved.value)
	sessOld, err := oldOnly.New(reqOld, "session")
	assertInvalid(t, sessOld, err, "")
}

func TestEncodingNeverFallsBackToRetiredKey(t *testing.T) {
	// The first codec has no authentication key and therefore cannot encode.
	// If encoding walked the codec list it would silently use the old key.
	store := &CookieStore{
		Codecs: securecookie.CodecsFromPairs(nil, oldHashKey),
		Options: &Options{
			Path: "/",
		},
	}
	session := NewSession(store, "session")
	session.Values["user"] = "alice"
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err == nil {
		t.Fatalf("expected encoding to fail instead of using the retired key")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("a cookie was issued despite the encoding failure")
	}
}

func TestTamperedAndTruncatedCookiesRejected(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)
	values := map[interface{}]interface{}{"user": "top-secret-user"}
	encoded := newEncodedSession(t, store, "session", values)

	flip := func(s string, i int) string {
		b := []byte(s)
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
		return string(b)
	}

	cases := []struct {
		name  string
		value string
	}{
		{"not base64", "!!!not-a-cookie!!!"},
		{"garbage", "Z29yYmFnZQ"},
		{"flipped first byte", flip(encoded, 0)},
		{"flipped middle byte", flip(encoded, len(encoded)/2)},
		{"flipped last byte", flip(encoded, len(encoded)-1)},
		{"truncated", encoded[:len(encoded)/2]},
		{"truncated by one", encoded[:len(encoded)-1]},
		{"extended", encoded + "AAAA"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := requestWithCookies("session=" + tc.value)
			session, err := store.New(req, "session")
			assertInvalid(t, session, err, "top-secret-user")
		})
	}

	// An empty value is not a tampering error: it is the marker browsers
	// leave after deleting a cookie, so it starts a fresh session and must
	// never resurrect any stored data.
	t.Run("empty", func(t *testing.T) {
		req := requestWithCookies("session=")
		session, err := store.New(req, "session")
		if err != nil {
			t.Fatalf("empty cookie: %v", err)
		}
		if !session.IsNew || len(session.Values) != 0 {
			t.Fatalf("empty cookie produced a session: new=%v values=%v",
				session.IsNew, session.Values)
		}
	})
}

func TestDuplicateCookies(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)

	cookieA := newEncodedSession(t, store, "session",
		map[interface{}]interface{}{"user": "alice"})
	cookieB := newEncodedSession(t, store, "session",
		map[interface{}]interface{}{"user": "mallory"})

	t.Run("identical duplicates accepted", func(t *testing.T) {
		// The same cookie sent twice is unambiguous.
		req := requestWithCookies(
			"session="+cookieA,
			"session="+cookieA,
		)
		session, err := store.New(req, "session")
		if err != nil {
			t.Fatalf("identical duplicates should be accepted: %v", err)
		}
		if session.IsNew || session.Values["user"] != "alice" {
			t.Fatalf("unexpected session: new=%v values=%v", session.IsNew, session.Values)
		}
	})

	t.Run("same line duplicates rejected", func(t *testing.T) {
		req := requestWithCookies("session=" + cookieA + "; session=" + cookieB)
		session, err := store.New(req, "session")
		assertInvalid(t, session, err, "mallory")
	})

	t.Run("split header duplicates rejected", func(t *testing.T) {
		req := requestWithCookies(
			"session="+cookieA,
			"session="+cookieB,
		)
		session, err := store.New(req, "session")
		assertInvalid(t, session, err, "mallory")
	})

	t.Run("valid plus tampered accepted", func(t *testing.T) {
		tampered := cookieB[:len(cookieB)-2] + "AA"
		req := requestWithCookies(
			"session="+tampered,
			"session="+cookieA,
		)
		session, err := store.New(req, "session")
		if err != nil {
			t.Fatalf("valid cookie alongside a tampered one should win: %v", err)
		}
		if session.Values["user"] != "alice" {
			t.Fatalf("bad value: %v", session.Values["user"])
		}
	})

	t.Run("empty plus valid accepted", func(t *testing.T) {
		// An empty cookie is what a browser leaves after deletion.
		req := requestWithCookies("session=", "session="+cookieA)
		session, err := store.New(req, "session")
		if err != nil {
			t.Fatalf("empty cookie alongside a valid one should be ignored: %v", err)
		}
		if session.IsNew || session.Values["user"] != "alice" {
			t.Fatalf("unexpected session: new=%v values=%v", session.IsNew, session.Values)
		}
	})

	t.Run("only empty cookie starts new session", func(t *testing.T) {
		req := requestWithCookies("session=")
		session, err := store.New(req, "session")
		if err != nil {
			t.Fatalf("empty cookie should not be an error: %v", err)
		}
		if !session.IsNew || len(session.Values) != 0 {
			t.Fatalf("expected a fresh session, got new=%v values=%v",
				session.IsNew, session.Values)
		}
	})
}

func TestCookieSizeLimits(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)

	// A session whose encoded form exceeds the limit cannot be saved.
	session := NewSession(store, "session")
	session.Options = &Options{MaxAge: 60}
	session.Values["big"] = strings.Repeat("x", 4096)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err == nil {
		t.Fatalf("expected oversized session to be rejected")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Fatalf("oversized session still set a cookie")
	}

	// Raising the limit allows the same session through.
	store.MaxLength(4096 * 4)
	rec = httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("Save with raised limit: %v", err)
	}
	saved := parseSetCookie(t, rec)

	// An oversized value presented in a request is rejected without being
	// decoded, and without being echoed in the error.
	store.MaxLength(16)
	reqIn := requestWithCookies("session=" + saved.value)
	sessionIn, err := store.New(reqIn, "session")
	assertInvalid(t, sessionIn, err, strings.Repeat("x", 32))
}

func TestCookieSavePreservesSecurityAttributes(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)
	store.Options = &Options{
		Path:     "/app",
		Domain:   "example.com",
		MaxAge:   3600,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}

	// A caller that replaces Options with only MaxAge set must not lose the
	// store's security attributes.
	session := NewSession(store, "session")
	session.Options = &Options{MaxAge: 120}
	session.Values["user"] = "alice"

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	saved := parseSetCookie(t, rec)

	if saved.value == "" {
		t.Fatalf("session data was not written")
	}
	if !saved.secure {
		t.Fatalf("Secure attribute lost on save")
	}
	if !saved.httpOnly {
		t.Fatalf("HttpOnly attribute lost on save")
	}
	if saved.sameSite != http.SameSiteLaxMode {
		t.Fatalf("SameSite lost on save: got %v", saved.sameSite)
	}
	if saved.path != "/app" {
		t.Fatalf("Path lost on save: got %q", saved.path)
	}
	if saved.domain != "example.com" {
		t.Fatalf("Domain lost on save: got %q", saved.domain)
	}
	if saved.maxAge != 120 {
		t.Fatalf("MaxAge not honored: got %d", saved.maxAge)
	}

	// The saved cookie must round-trip and keep the values.
	req2 := requestWithCookies("session=" + saved.value)
	roundTripped, err := store.New(req2, "session")
	if err != nil {
		t.Fatalf("New after save: %v", err)
	}
	if roundTripped.IsNew || roundTripped.Values["user"] != "alice" {
		t.Fatalf("round trip failed: new=%v values=%v",
			roundTripped.IsNew, roundTripped.Values)
	}
}

func TestCookieSaveExpiresWithoutLeakingData(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)
	store.Options = &Options{
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}

	session := NewSession(store, "session")
	session.Values["user"] = "top-secret-user"
	session.Options = &Options{MaxAge: -1}

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	rec := httptest.NewRecorder()
	if err := session.Save(req, rec); err != nil {
		t.Fatalf("Save: %v", err)
	}
	saved := parseSetCookie(t, rec)

	if saved.value != "" {
		t.Fatalf("expired cookie still carries session data: %q", saved.value)
	}
	if saved.maxAge >= 0 {
		t.Fatalf("expired cookie MaxAge should be negative, got %d", saved.maxAge)
	}
	if !saved.secure || !saved.httpOnly || saved.sameSite != http.SameSiteStrictMode {
		t.Fatalf("expired cookie lost security attributes: %+v", saved)
	}

	// A client presenting the deletion cookie starts a new session.
	req2 := requestWithCookies("session=")
	fresh, err := store.New(req2, "session")
	if err != nil {
		t.Fatalf("empty deletion cookie should not error: %v", err)
	}
	if !fresh.IsNew || len(fresh.Values) != 0 {
		t.Fatalf("deletion cookie produced an existing session: %v", fresh.Values)
	}
}

func TestRegistryConcurrentGetAndSave(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reg := GetRegistry(req)

	const goroutines = 64
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			name := fmt.Sprintf("session-%d", i%8)
			session, err := reg.Get(store, name)
			if err != nil {
				errs <- err
				return
			}
			if session == nil {
				errs <- fmt.Errorf("nil session for %q", name)
				return
			}
			// Each goroutine saves into its own response recorder; the
			// request registry is shared.
			rec := httptest.NewRecorder()
			if err := reg.Save(rec); err != nil {
				errs <- err
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent Get/Save: %v", err)
	}

	// The registry must hold one session per distinct name.
	for i := 0; i < 8; i++ {
		session, err := reg.Get(store, fmt.Sprintf("session-%d", i))
		if err != nil {
			t.Fatalf("Get after concurrency: %v", err)
		}
		if session == nil || session.Name() != fmt.Sprintf("session-%d", i) {
			t.Fatalf("bad session %d after concurrency: %v", i, session)
		}
	}
}

func TestCookieStoreConcurrentSaveAndRead(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)

	const goroutines = 32
	var wg sync.WaitGroup
	start := make(chan struct{})
	errs := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
			session, err := store.New(req, "session")
			if err != nil {
				errs <- err
				return
			}
			session.Values["id"] = i
			rec := httptest.NewRecorder()
			if err := session.Save(req, rec); err != nil {
				errs <- err
				return
			}
			cookies := rec.Result().Cookies()
			if len(cookies) != 1 {
				errs <- fmt.Errorf("expected one cookie, got %d", len(cookies))
				return
			}
			readReq := requestWithCookies("session=" + cookies[0].Value)
			read, err := store.New(readReq, "session")
			if err != nil {
				errs <- err
				return
			}
			if read.Values["id"] != i {
				errs <- fmt.Errorf("cookie %d decoded as %v", i, read.Values["id"])
			}
		}(i)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatalf("concurrent save/read: %v", err)
	}
}

func TestFilesystemStoreDuplicateAndTamperedCookies(t *testing.T) {
	dir := t.TempDir()
	store := NewFilesystemStore(dir, newHashKey, newBlockKey)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	session, err := store.New(req, "session")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session.Values["user"] = "alice"
	saved := saveSession(t, store, session)

	// A tampered cookie is rejected as invalid and does not leak the ID or
	// the file path.
	bad := saved.value[:len(saved.value)-2] + "AA"
	reqBad := requestWithCookies("session=" + bad)
	sessBad, err := store.New(reqBad, "session")
	assertInvalid(t, sessBad, err, "")

	// Duplicate valid cookies with different IDs are ambiguous.
	req2 := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	session2, err := store.New(req2, "session")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session2.Values["user"] = "mallory"
	saved2 := saveSession(t, store, session2)

	reqDup := requestWithCookies("session="+saved.value, "session="+saved2.value)
	sessDup, err := store.New(reqDup, "session")
	assertInvalid(t, sessDup, err, "")

	// Identical duplicates are accepted.
	reqSame := requestWithCookies("session="+saved.value, "session="+saved.value)
	sessSame, err := store.New(reqSame, "session")
	if err != nil {
		t.Fatalf("identical duplicates rejected: %v", err)
	}
	if sessSame.IsNew || sessSame.Values["user"] != "alice" {
		t.Fatalf("unexpected session: new=%v values=%v", sessSame.IsNew, sessSame.Values)
	}
}

func TestFilesystemStoreRejectsTamperedSessionFile(t *testing.T) {
	dir := t.TempDir()
	store := NewFilesystemStore(dir, newHashKey, newBlockKey)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	session, err := store.New(req, "session")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session.Values["user"] = "top-secret-user"
	saved := saveSession(t, store, session)

	// Corrupt the session file on disk; the signed ID is still authentic,
	// so only the payload signature can catch the tampering.
	path := filepath.Join(dir, sessionFilePrefix+session.ID)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read session file: %v", err)
	}
	if err := os.WriteFile(path, append(data, 'A'), 0600); err != nil {
		t.Fatalf("write session file: %v", err)
	}

	reqRead := requestWithCookies("session=" + saved.value)
	sessRead, err := store.New(reqRead, "session")
	assertInvalid(t, sessRead, err, "top-secret-user")
}

func TestFilesystemStoreRotation(t *testing.T) {
	dir := t.TempDir()
	oldStore := NewFilesystemStore(dir, oldHashKey, oldBlockKey)
	rotated := NewFilesystemStore(dir, newHashKey, newBlockKey, oldHashKey, oldBlockKey)
	oldOnly := NewFilesystemStore(dir, oldHashKey, oldBlockKey)

	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	session, err := oldStore.New(req, "session")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	session.Values["user"] = "alice"
	saved := saveSession(t, oldStore, session)

	// The rotated store reads the old cookie and re-signs with the new key.
	reqOld := requestWithCookies("session=" + saved.value)
	sess, err := rotated.New(reqOld, "session")
	if err != nil {
		t.Fatalf("rotated store rejected old cookie: %v", err)
	}
	if sess.IsNew || sess.Values["user"] != "alice" {
		t.Fatalf("bad session: new=%v values=%v", sess.IsNew, sess.Values)
	}
	resaved := saveSession(t, rotated, sess)
	if resaved.value == saved.value {
		t.Fatalf("Save reused the old cookie instead of re-signing")
	}
	if _, err := oldOnly.New(requestWithCookies("session="+resaved.value), "session"); err == nil {
		t.Fatalf("retired key accepted a cookie signed with the new key")
	}
}

func TestRegistryGetRejectsUnicodeCookieNameBeforeRegistration(t *testing.T) {
	store := NewCookieStore(newHashKey, newBlockKey)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reg := GetRegistry(req)

	session, err := reg.Get(store, "session:name")
	if err == nil {
		t.Fatalf("expected invalid cookie name error")
	}
	if session != nil {
		t.Fatalf("invalid cookie name returned a session")
	}
}

// blockingStore is a test store whose New blocks until release is closed, so
// that concurrent Gets can be shown to converge on one instance.
type blockingStore struct {
	release  chan struct{}
	inNew    chan struct{}
	sessions map[string]*Session
}

func (s *blockingStore) Get(r *http.Request, name string) (*Session, error) {
	return nil, fmt.Errorf("not used")
}

func (s *blockingStore) New(r *http.Request, name string) (*Session, error) {
	s.inNew <- struct{}{}
	<-s.release
	session := NewSession(s, name)
	session.Values["count"] = 1
	return session, nil
}

func (s *blockingStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	return nil
}

func TestRegistryConcurrentGetReturnsOneInstance(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reg := GetRegistry(req)
	store := &blockingStore{
		release: make(chan struct{}),
		inNew:   make(chan struct{}, 64),
	}

	const goroutines = 32
	var wg sync.WaitGroup
	results := make([]*Session, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			results[i], _ = reg.Get(store, "shared")
		}(i)
	}

	// Release the loader(s) once at least one is inside store.New.
	<-store.inNew
	close(store.release)
	wg.Wait()

	first := results[0]
	if first == nil {
		t.Fatalf("Get returned nil session")
	}
	for i, session := range results {
		if session != first {
			t.Fatalf("goroutine %d got a different session instance", i)
		}
	}
}

// reentrantStore calls back into the registry from inside New. The registry
// must not hold its lock while calling New, or this deadlocks.
type reentrantStore struct {
	reg      *Registry
	reentred bool
}

func (s *reentrantStore) Get(r *http.Request, name string) (*Session, error) {
	return s.reg.Get(s, name)
}

func (s *reentrantStore) New(r *http.Request, name string) (*Session, error) {
	if !s.reentred {
		s.reentred = true
		// A nested lookup for a different name must complete normally.
		if _, err := s.reg.Get(s, "nested"); err != nil {
			return nil, err
		}
	}
	return NewSession(s, name), nil
}

func (s *reentrantStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	return nil
}

func TestRegistryStoreMayCallBackIntoRegistry(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reg := GetRegistry(req)
	store := &reentrantStore{reg: reg}

	session, err := reg.Get(store, "outer")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if session == nil {
		t.Fatalf("Get returned nil session")
	}
	if _, err := reg.Get(store, "nested"); err != nil {
		t.Fatalf("nested Get: %v", err)
	}
}

// nilSessionStore violates the Store contract by returning a nil session
// with no error; the registry must not panic or hand back nil.
type nilSessionStore struct{}

func (s *nilSessionStore) Get(r *http.Request, name string) (*Session, error) {
	return nil, nil
}

func (s *nilSessionStore) New(r *http.Request, name string) (*Session, error) {
	return nil, nil
}

func (s *nilSessionStore) Save(r *http.Request, w http.ResponseWriter, session *Session) error {
	return fmt.Errorf("not used")
}

func TestRegistryGetWithNilSessionStore(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reg := GetRegistry(req)
	store := &nilSessionStore{}

	session, err := reg.Get(store, "session")
	if err == nil {
		t.Fatalf("expected an error for a nil session")
	}
	if session != nil {
		t.Fatalf("expected nil session alongside the error")
	}

	// Save must report the problem instead of panicking.
	rec := httptest.NewRecorder()
	if err := reg.Save(rec); err == nil {
		t.Fatalf("expected Save to report the missing session/store")
	}
}
