package sessionauth

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type Session struct {
	Username  string
	ExpiresAt time.Time
}

type Manager struct {
	username     string
	passwordHash []byte
	cookieName   string
	ttl          time.Duration
	secure       bool

	mu       sync.RWMutex
	sessions map[string]Session
}

func New(username, passwordHash, cookieName string, ttl time.Duration, secure bool) (*Manager, error) {
	if username == "" {
		return nil, errors.New("username is required")
	}
	if passwordHash == "" {
		return nil, errors.New("password hash is required")
	}
	if cookieName == "" {
		cookieName = "fireslice_session"
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	return &Manager{
		username:     username,
		passwordHash: []byte(passwordHash),
		cookieName:   cookieName,
		ttl:          ttl,
		secure:       secure,
		sessions:     make(map[string]Session),
	}, nil
}

func (m *Manager) Login(username, password string) (string, error) {
	if username != m.username {
		return "", errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword(m.passwordHash, []byte(password)); err != nil {
		return "", errors.New("invalid credentials")
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.sessions[token] = Session{Username: username, ExpiresAt: time.Now().Add(m.ttl)}
	m.mu.Unlock()
	return token, nil
}

func (m *Manager) Logout(token string) {
	m.mu.Lock()
	delete(m.sessions, token)
	m.mu.Unlock()
}

func (m *Manager) Session(token string) (Session, bool) {
	m.mu.RLock()
	session, ok := m.sessions[token]
	m.mu.RUnlock()
	if !ok {
		return Session{}, false
	}
	if time.Now().After(session.ExpiresAt) {
		m.Logout(token)
		return Session{}, false
	}
	return session, true
}

func (m *Manager) SetSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(m.ttl),
	})
}

func (m *Manager) ClearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   m.secure,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func (m *Manager) CookieName() string {
	return m.cookieName
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}
