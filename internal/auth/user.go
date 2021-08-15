// Copyright 2021 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"errors"
	"sync"
)

type Role string

const (
	UserRole  Role = "user"
	AdminRole Role = "admin"
)

type UserStore interface {
	Save(user *User) error
	Get(username string) (*User, error)
}

func NewUserStore() *InMemoryUserStore {
	return &InMemoryUserStore{
		users: make(map[string]*User),
	}
}

type User struct {
	Username string
	Password []byte // hashed
	Role     Role
}

type InMemoryUserStore struct {
	mutex sync.RWMutex
	users map[string]*User
}

func (u User) Clone() *User {
	b := make([]byte, len(u.Password))
	copy(b, u.Password)
	return &User{
		Username: u.Username,
		Password: b,
		Role:     u.Role,
	}
}

func (store *InMemoryUserStore) Save(user *User) error {
	store.mutex.Lock()
	defer store.mutex.Unlock()

	if store.users[user.Username] != nil {
		return errors.New("user exists")
	}

	store.users[user.Username] = user.Clone()
	return nil
}

func (store *InMemoryUserStore) Get(username string) (*User, error) {
	store.mutex.RLock()
	defer store.mutex.RUnlock()

	user := store.users[username]
	if user == nil {
		return nil, errors.New("user not found")
	}

	return user.Clone(), nil
}
