package sessionauth

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/mojomast/fireslice/internal/db"
	"golang.org/x/crypto/bcrypt"
)

type AuthUser struct {
	ID             int64
	Handle         string
	Role           string
	PasswordBcrypt string
}

type UserLookup interface {
	GetUserByHandle(handle string) (*AuthUser, error)
}

type Session struct {
	UserID    int64
	Username  string
	Role      string
	ExpiresAt time.Time
}

type Manager struct {
	lookup            UserLookup
	bootstrapUsername string
	bootstrapHash     []byte
	cookieName        string
	ttl               time.Duration
	secure            bool

	mu       sync.RWMutex
	sessions map[string]Session
}

func New(lookup UserLookup, bootstrapUsername, bootstrapPasswordHash, cookieName string, ttl time.Duration, secure bool) (*Manager, error) {
	if cookieName == "" {
		cookieName = "fireslice_session"
	}
	if ttl <= 0 {
		ttl = 24 * time.Hour
	}
	if lookup == nil && (bootstrapUsername == "" || bootstrapPasswordHash == "") {
		return nil, errors.New("auth lookup or bootstrap admin credentials are required")
	}
	return &Manager{
		lookup:            lookup,
		bootstrapUsername: bootstrapUsername,
		bootstrapHash:     []byte(bootstrapPasswordHash),
		cookieName:        cookieName,
		ttl:               ttl,
		secure:            secure,
		sessions:          make(map[string]Session),
	}, nil
}

func (m *Manager) Login(username, password string) (string, error) {
	user, err := m.authenticate(username, password)
	if err != nil {
		return "", err
	}
	token, err := randomToken()
	if err != nil {
		return "", err
	}
	m.mu.Lock()
	m.sessions[token] = Session{
		UserID:    user.ID,
		Username:  user.Handle,
		Role:      user.Role,
		ExpiresAt: time.Now().Add(m.ttl),
	}
	m.mu.Unlock()
	return token, nil
}

func (m *Manager) authenticate(username, password string) (*AuthUser, error) {
	if username == m.bootstrapUsername && len(m.bootstrapHash) > 0 {
		if err := bcrypt.CompareHashAndPassword(m.bootstrapHash, []byte(password)); err == nil {
			return &AuthUser{Handle: username, Role: "admin"}, nil
		}
	}
	if m.lookup == nil {
		return nil, errors.New("invalid credentials")
	}
	user, err := m.lookup.GetUserByHandle(username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("invalid credentials")
		}
		return nil, err
	}
	if user == nil || user.PasswordBcrypt == "" {
		return nil, errors.New("invalid credentials")
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordBcrypt), []byte(password)); err != nil {
		return nil, errors.New("invalid credentials")
	}
	if user.Role == "" {
		user.Role = "user"
	}
	return user, nil
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

type DBLookup struct{ DB *db.DB }

func (l *DBLookup) GetUserByHandle(handle string) (*AuthUser, error) {
	user, err := l.DB.GetFiresliceUserByHandle(context.Background(), rstrip(handle))
	if err != nil {
		return nil, err
	}
	return &AuthUser{
		ID:             user.ID,
		Handle:         user.Handle,
		Role:           user.Role,
		PasswordBcrypt: user.PasswordBcrypt,
	}, nil
}

func randomToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func rstrip(s string) string {
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\n' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}
