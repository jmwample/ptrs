package main

import (
	"fmt"
	"log/slog"
	"net"
	"strings"
)

const (
	elidedAddr = "[scrubbed]"
)

var unsafeLogging bool

// SetLogLevel sets the log level to the value indicated by the given string
// (case-insensitive).
func parseLevel(logLevelStr string) (*slog.Level, error) {
	logLevel := slog.LevelInfo
	switch strings.ToUpper(logLevelStr) {
	case "ERROR":
		logLevel = slog.LevelError
	case "WARN":
		logLevel = slog.LevelWarn
	case "INFO":
		logLevel = slog.LevelInfo
	case "DEBUG":
		logLevel = slog.LevelDebug
	default:
		return nil, fmt.Errorf("invalid log level '%s'", logLevelStr)
	}
	return &logLevel, nil
}

// ElideError transforms the string representation of the provided error
// based on the unsafeLogging setting.  Callers that wish to log errors
// returned from Go's net package should use ElideError to sanitize the
// contents first.
func elideError(err error) string {
	// Go's net package is somewhat rude and includes IP address and port
	// information in the string representation of net.Errors.  Figure out if
	// this is the case here, and sanitize the error messages as needed.
	if unsafeLogging {
		return err.Error()
	}

	// If err is not a net.Error, just return the string representation,
	// presumably transport authors know what they are doing.
	netErr, ok := err.(net.Error)
	if !ok {
		return err.Error()
	}

	switch t := netErr.(type) {
	case *net.AddrError:
		return t.Err + " " + elidedAddr
	case *net.DNSError:
		return "lookup " + elidedAddr + " on " + elidedAddr + ": " + t.Err
	case *net.InvalidAddrError:
		return "invalid address error"
	case *net.UnknownNetworkError:
		return "unknown network " + elidedAddr
	case *net.OpError:
		return t.Op + ": " + t.Err.Error()
	default:
		// For unknown error types, do the conservative thing and only log the
		// type of the error instead of assuming that the string representation
		// does not contain sensitive information.
		return fmt.Sprintf("network error: <%T>", t)
	}
}

// ElideAddr transforms the string representation of the provided address based
// on the unsafeLogging setting.  Callers that wish to log IP addreses should
// use ElideAddr to sanitize the contents first.
func elideAddr(addrStr string) string {
	if unsafeLogging {
		return addrStr
	}

	// Only scrub off the address so that it's easier to track connections
	// in logs by looking at the port.
	if _, port, err := net.SplitHostPort(addrStr); err == nil {
		return elidedAddr + ":" + port
	}
	return elidedAddr
}

func Infof(format string, args ...any) {
	slog.Info(fmt.Sprintf(format, args...))
}

func Warnf(format string, args ...any) {
	slog.Warn(fmt.Sprintf(format, args...))
}

func Debugf(format string, args ...any) {
	slog.Debug(fmt.Sprintf(format, args...))
}

func Errorf(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
}
