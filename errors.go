package main

import (
	"fmt"
	"net/http"
)

type PwnyXprsError interface {
	error
	Status() int
}

type MalformedRequestError struct {
	Message string
}

type AuthError struct{}

type InternalError struct {
	Message *string
}

func (e MalformedRequestError) Error() string {
	return fmt.Sprintf("malformed request: %s", e.Message)
}

func (e MalformedRequestError) Status() int {
	return http.StatusBadRequest
}

func (e AuthError) Error() string {
	return "invalid master password"
}

func (e AuthError) Status() int {
	return http.StatusForbidden
}

func (e InternalError) Error() string {
	if e.Message == nil {
		return "internal error"
	} else {
		return fmt.Sprintf("internal error: %s", *e.Message)
	}
}

func (e InternalError) Status() int {
	return http.StatusInternalServerError
}
