package control

import (
	"context"
	"fmt"
	"time"

	"edr/internal/collector"
	"edr/internal/eventlog"
	"edr/internal/policy"
	"edr/internal/response"
)

// Phase 1 refactor contracts: keep the single-binary runtime, but route
// the core responsibilities through stable interfaces so sensor /
// orchestrator / enforcer can split without rewriting the call graph.
type EventSource interface {
	Snapshot(context.Context) (collector.Snapshot, error)
}

type DecisionEngine interface {
	EvaluateProcessAccess(policy.Subject) (policy.Rule, bool)
	EvaluateAll(time.Time, policy.Subject, policy.Object) []policy.Rule
}

type ActionExecutor interface {
	Apply(response.ActionRequest) response.Result
}

type AuditSink interface {
	Write(eventlog.Event) error
}

type CollectorSource struct {
	Collector collector.Collector
}

func (s CollectorSource) Snapshot(_ context.Context) (collector.Snapshot, error) {
	if s.Collector == nil {
		return collector.Snapshot{}, fmt.Errorf("collector not configured")
	}
	return s.Collector.Snapshot()
}

type PolicyEngine struct {
	Policy *policy.Policy
}

func (e PolicyEngine) EvaluateProcessAccess(subj policy.Subject) (policy.Rule, bool) {
	if e.Policy == nil {
		return policy.Rule{}, false
	}
	return e.Policy.EvaluateProcessAccess(subj)
}

func (e PolicyEngine) EvaluateAll(now time.Time, subj policy.Subject, obj policy.Object) []policy.Rule {
	if e.Policy == nil {
		return nil
	}
	return e.Policy.EvaluateAll(now, subj, obj)
}

type LoggerSink struct {
	Logger *eventlog.Logger
}

func (s LoggerSink) Write(ev eventlog.Event) error {
	if s.Logger == nil {
		return fmt.Errorf("logger not configured")
	}
	return s.Logger.Write(ev)
}

type ResponderExecutor struct {
	Responder response.Responder
}

func (e ResponderExecutor) Apply(req response.ActionRequest) response.Result {
	if e.Responder == nil {
		return response.Result{Action: req.Action, Success: false, Detail: "responder not configured"}
	}
	return e.Responder.Apply(req)
}
