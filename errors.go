package policysdk

import "fmt"

type ErrorKind string

const (
	ErrorKindAuthentication ErrorKind = "authentication"
	ErrorKindAuthorization  ErrorKind = "authorization"
	ErrorKindServer         ErrorKind = "server"
	ErrorKindTransport      ErrorKind = "transport"
	ErrorKindConfiguration  ErrorKind = "configuration"
)

type Error struct {
	Kind       ErrorKind
	Message    string
	StatusCode int
	Cause      error
}

func (e *Error) Error() string {
	if e == nil {
		return ""
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("%s (status %d)", e.Message, e.StatusCode)
	}
	return e.Message
}

func (e *Error) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Cause
}
