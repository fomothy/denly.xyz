package main

import (
	"strings"
	"testing"
)

func TestRunNoArgsShowsUsage(t *testing.T) {
	if err := run(nil); err != nil {
		t.Errorf("run(nil) = %v, want nil", err)
	}
}

func TestRunHelp(t *testing.T) {
	for _, arg := range []string{"help", "--help", "-h"} {
		if err := run([]string{arg}); err != nil {
			t.Errorf("run(%q) = %v, want nil", arg, err)
		}
	}
}

func TestRunVersion(t *testing.T) {
	for _, arg := range []string{"version", "--version", "-v"} {
		if err := run([]string{arg}); err != nil {
			t.Errorf("run(%q) = %v, want nil", arg, err)
		}
	}
}

func TestRunVersionJSON(t *testing.T) {
	if err := run([]string{"version", "-json"}); err != nil {
		t.Errorf("run(version -json) = %v, want nil", err)
	}
}

func TestRunUnknownCommandErrors(t *testing.T) {
	err := run([]string{"frobnicate"})
	if err == nil {
		t.Fatal("run with unknown command returned nil, want error")
	}
	if !strings.Contains(err.Error(), "unknown command") {
		t.Errorf("err = %v, want it to mention the unknown command", err)
	}
}

func TestNewLoggerVariants(t *testing.T) {
	if newLogger(false, false) == nil {
		t.Error("text logger is nil")
	}
	if newLogger(true, true) == nil {
		t.Error("json logger is nil")
	}
}
