package main

import "testing"

func TestAgentOutputCannotBeMixedWithOtherCompleteFormats(t *testing.T) {
	for _, o := range []*options{
		{agentOut: true, jsonOut: true},
		{agentOut: true, csvOut: true},
		{agentOut: true, plain: true},
	} {
		if err := validateFlags(o); err == nil {
			t.Fatalf("conflicting output modes were accepted: %+v", o)
		}
	}
	if err := validateFlags(&options{agentOut: true}); err != nil {
		t.Fatalf("agent output alone was rejected: %v", err)
	}
}
