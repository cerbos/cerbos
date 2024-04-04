// Copyright 2021-2024 Zenauth Ltd.
// SPDX-License-Identifier: Apache-2.0

package hub

type stack[T any] struct {
	head   *node[T]
	length int
}

type node[T any] struct {
	value T
	prev  *node[T]
}

func newStack[T any]() *stack[T] {
	return &stack[T]{nil, 0}
}

func (s *stack[T]) len() int {
	return s.length
}

func (s *stack[T]) peek() (T, bool) {
	var zero T
	if s.length == 0 {
		return zero, false
	}
	return s.head.value, true
}

func (s *stack[T]) pop() (T, bool) {
	var zero T
	if s.length == 0 {
		return zero, false
	}

	n := s.head
	s.head = n.prev
	s.length--
	return n.value, true
}

func (s *stack[T]) push(value T) {
	n := &node[T]{value, s.head}
	s.head = n
	s.length++
}
