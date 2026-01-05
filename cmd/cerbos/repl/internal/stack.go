// Copyright 2021-2026 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package internal

type runeStack []rune

func (s *runeStack) Push(r rune) {
	*s = append(*s, r)
}

func (s *runeStack) Pop() (rune, bool) {
	l := len(*s)
	if l == 0 {
		return -1, false
	}

	v := (*s)[l-1]
	*s = (*s)[:l-1]

	return v, true
}

func (s *runeStack) Peek() (rune, bool) {
	l := len(*s)
	if l == 0 {
		return -1, false
	}

	return (*s)[l-1], true
}

func (s *runeStack) IsEmpty() bool {
	return len(*s) == 0
}
