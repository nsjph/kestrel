package main

const (
	ERROR_NONE                = 0
	ERROR_MALFORMED_ADDRESS   = 1
	ERROR_FLOOD               = 2
	ERROR_LINK_LIMIT_EXCEEDED = 3
	ERROR_OVERSIZE_MESSAGE    = 4
	ERROR_UNDERSIZE_MESSAGE   = 5
	ERROR_AUTHENTICATION      = 6
	ERROR_INVALID             = 7
	ERROR_UNDELIVERABLE       = 8
	ERROR_LOOP_ROUTE          = 9
	ERROR_RETURN_PATH_INVALID = 10
	ERROR_UNKNOWN             = 11
	ERROR_NOT_IMPLEMENTED     = 12
)

var (
	cjdnsErrors = map[int]string{
		0:  "ERROR_NONE",
		1:  "ERROR_MALFORMED_ADDRESS",
		2:  "ERROR_FLOOD",
		3:  "ERROR_LINK_LIMIT_EXCEEDED",
		4:  "ERROR_OVERSIZE_MESSAGE",
		5:  "ERROR_UNDERSIZE_MESSAGE",
		6:  "ERROR_AUTHENTICATION",
		7:  "ERROR_INVALID",
		8:  "ERROR_UNDELIVERABLE",
		9:  "ERROR_LOOP_ROUTE",
		10: "ERROR_RETURN_PATH_INVALID",
		11: "ERROR_UNKNOWN",
		12: "ERROR_NOT_IMPLEMENTED",
	}
	errNone              = newError(0, "No error")
	errMalformedAddress  = newError(1, "Malformed address")
	errFlood             = newError(2, "Traffic flood")
	errLinkLimitExceeded = newError(3, "Link limit exceeded")
	errOverSizeMessage   = newError(4, "Oversize message")
	errUndersizeMessage  = newError(5, "Undersize message")
	errAuthentication    = newError(6, "Authentication error")
	errInvalid           = newError(7, "Invalid") // TODO: check what/when raises this type of error
	errUndeliverable     = newError(8, "Undeliverable")
	errLoopRoute         = newError(9, "Invalid route due to loop")
	errReturnPathInvalid = newError(10, "Invalid return path")
	errUnknown           = newError(11, "Unknown Error")
	errNotImplemented    = newError(12, "Feature not implemented")
)

// type protocolError interface {
// 	error
// 	Timeout() bool
// 	Temporary() bool
// }

// type OpError struct {
// 	Op   string // type of operation being performed at time of error
// 	Addr Addr   // peer Address where this occured
// 	Err  error
// }

// Still experimenting with the right approach to handling cjdns-related errors in an
// extensible way. Expect change and placeholders.

type cjdnsError struct {
	Code      int
	Message   string
	Details   string
	Timeout   bool // is error a timeout?
	Temporary bool // is error temporary?
	Err       error
}

//func newError(errcode int, errmsg string, isTimeoutError bool, isTemporaryError bool) *cjdnsError {

func newError(errcode int, errmsg string) *cjdnsError {
	err := &cjdnsError{
		Code:      errcode,
		Message:   errmsg,
		Details:   "",
		Timeout:   false,
		Temporary: false,
	}

	return err
}

func (err *cjdnsError) Error() string {
	return err.Message
}

// addDetails lets you leverage an existing default message type, such as
// errUndeliverable, but allows you to add extra details to the error message
//
// TODO: Check if this is performant, or if there's a better way to do same thing
//
// example: return errUndeliverable.addDetails("decryption failed")
func (err cjdnsError) addDetails(details string) *cjdnsError {
	detailedErr := err
	detailedErr.Details = details
	return &detailedErr
}

func (err *cjdnsError) isTimeout() bool {
	return err.Timeout
}

func (err *cjdnsError) isTemporary() bool {
	return err.Temporary
}
