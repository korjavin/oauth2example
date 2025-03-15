package logger

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// LogLevel represents the severity level of a log message
type LogLevel int

const (
	// DebugLevel is for detailed debugging information
	DebugLevel LogLevel = iota
	// InfoLevel is for general operational information
	InfoLevel
	// WarnLevel is for warnings that don't affect operation
	WarnLevel
	// ErrorLevel is for errors that affect operation
	ErrorLevel
	// DisabledLevel turns off all logging
	DisabledLevel
)

// Logger provides educational logging for the OAuth2 flow
type Logger struct {
	level  LogLevel
	writer io.Writer
}

// New creates a new Logger with the specified log level
func New(level LogLevel) *Logger {
	return &Logger{
		level:  level,
		writer: os.Stdout,
	}
}

// SetWriter sets the output writer for the logger
func (l *Logger) SetWriter(w io.Writer) {
	l.writer = w
}

// SetLevel sets the minimum log level
func (l *Logger) SetLevel(level LogLevel) {
	l.level = level
}

// formatMessage formats a log message with timestamp and level
func (l *Logger) formatMessage(level LogLevel, message string) string {
	levelStr := ""
	switch level {
	case DebugLevel:
		levelStr = "DEBUG"
	case InfoLevel:
		levelStr = "INFO "
	case WarnLevel:
		levelStr = "WARN "
	case ErrorLevel:
		levelStr = "ERROR"
	}

	timestamp := time.Now().Format("15:04:05.000")
	return fmt.Sprintf("[%s] %s: %s", timestamp, levelStr, message)
}

// log logs a message at the specified level
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	message := fmt.Sprintf(format, args...)
	formattedMessage := l.formatMessage(level, message)

	// For multi-line educational messages, indent subsequent lines
	lines := strings.Split(formattedMessage, "\n")
	if len(lines) > 1 {
		for i := 1; i < len(lines); i++ {
			lines[i] = "                " + lines[i]
		}
		formattedMessage = strings.Join(lines, "\n")
	}

	fmt.Fprintln(l.writer, formattedMessage)
}

// Debug logs a debug message
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DebugLevel, format, args...)
}

// Info logs an info message
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(InfoLevel, format, args...)
}

// Warn logs a warning message
func (l *Logger) Warn(format string, args ...interface{}) {
	l.log(WarnLevel, format, args...)
}

// Error logs an error message
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ErrorLevel, format, args...)
}

// Educational logs an educational message about the OAuth2 flow
func (l *Logger) Educational(topic string, message string) {
	if l.level > InfoLevel {
		return
	}

	header := fmt.Sprintf("📚 EDUCATIONAL: %s", strings.ToUpper(topic))
	separator := strings.Repeat("-", len(header))

	l.Info("\n%s\n%s\n%s\n", separator, header, separator)
	l.Info("%s", message)
	l.Info("%s\n", separator)
}

// Step logs a step in the OAuth2 flow process
func (l *Logger) Step(stepNumber int, stepName string, description string) {
	if l.level > InfoLevel {
		return
	}

	l.Info("STEP %d: %s", stepNumber, strings.ToUpper(stepName))
	l.Info("  %s", description)
}

// DefaultLogger is the default logger instance
var DefaultLogger = New(InfoLevel)

// SetDefaultLogLevel sets the log level for the default logger
func SetDefaultLogLevel(level LogLevel) {
	DefaultLogger.SetLevel(level)
}

// Debug logs a debug message to the default logger
func Debug(format string, args ...interface{}) {
	DefaultLogger.Debug(format, args...)
}

// Info logs an info message to the default logger
func Info(format string, args ...interface{}) {
	DefaultLogger.Info(format, args...)
}

// Warn logs a warning message to the default logger
func Warn(format string, args ...interface{}) {
	DefaultLogger.Warn(format, args...)
}

// Error logs an error message to the default logger
func Error(format string, args ...interface{}) {
	DefaultLogger.Error(format, args...)
}

// Educational logs an educational message to the default logger
func Educational(topic string, message string) {
	DefaultLogger.Educational(topic, message)
}

// Step logs a step in the OAuth2 flow process to the default logger
func Step(stepNumber int, stepName string, description string) {
	DefaultLogger.Step(stepNumber, stepName, description)
}
