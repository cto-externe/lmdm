// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package deployments

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/cto-externe/lmdm/internal/profiles"
)

// -----------------------------------------------------------------------------
// Fakes — kept in this file (not testutil) because they are specific to the
// state-machine tests and closely mirror the subset of methods Engine calls.
// -----------------------------------------------------------------------------

// fakeRepo is an in-memory implementation of repoIface. It keeps deployments
// and per-device results in maps keyed by deployment ID; tenant lookups go
// through a secondary map populated at Create time.
type fakeRepo struct {
	mu          sync.Mutex
	deployments map[uuid.UUID]*Deployment
	results     map[uuid.UUID]map[uuid.UUID]Result // depID → devID → Result
}

func newFakeRepo() *fakeRepo {
	return &fakeRepo{
		deployments: make(map[uuid.UUID]*Deployment),
		results:     make(map[uuid.UUID]map[uuid.UUID]Result),
	}
}

func (f *fakeRepo) Create(_ context.Context, tenantID uuid.UUID, in Deployment) (*Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d := in
	d.ID = uuid.New()
	d.TenantID = tenantID
	d.CreatedAt = time.Now()
	if d.Status == "" {
		d.Status = StatusPlanned
	}
	if d.ValidationMode == "" {
		d.ValidationMode = ModeManual
	}
	cp := d
	f.deployments[d.ID] = &cp
	f.results[d.ID] = make(map[uuid.UUID]Result)
	out := cp
	return &out, nil
}

func (f *fakeRepo) FindByID(_ context.Context, _ uuid.UUID, id uuid.UUID) (*Deployment, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return nil, ErrNotFound
	}
	cp := *d
	return &cp, nil
}

func (f *fakeRepo) FindTenantForDeployment(_ context.Context, id uuid.UUID) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return uuid.Nil, ErrNotFound
	}
	return d.TenantID, nil
}

func (f *fakeRepo) UpdateStatus(_ context.Context, _, id uuid.UUID, s Status, reason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return ErrNotFound
	}
	d.Status = s
	if reason != "" {
		d.Reason = reason
	}
	return nil
}

func (f *fakeRepo) SetCanaryStarted(_ context.Context, _, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	d.CanaryStartedAt = &now
	return nil
}

func (f *fakeRepo) SetCanaryFinished(_ context.Context, _, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	d.CanaryFinishedAt = &now
	return nil
}

func (f *fakeRepo) SetValidated(_ context.Context, _, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	d.ValidatedAt = &now
	return nil
}

func (f *fakeRepo) SetCompleted(_ context.Context, _, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	d, ok := f.deployments[id]
	if !ok {
		return ErrNotFound
	}
	now := time.Now()
	d.CompletedAt = &now
	return nil
}

func (f *fakeRepo) UpsertResult(_ context.Context, _, depID, devID uuid.UUID, in Result) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	m, ok := f.results[depID]
	if !ok {
		m = make(map[uuid.UUID]Result)
		f.results[depID] = m
	}
	in.DeviceID = devID
	in.DeploymentID = depID
	m[devID] = in
	return nil
}

func (f *fakeRepo) ListResults(_ context.Context, _, depID uuid.UUID) ([]Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	m := f.results[depID]
	out := make([]Result, 0, len(m))
	for _, r := range m {
		out = append(out, r)
	}
	return out, nil
}

// status snapshot helper used in assertions to avoid racing on the map.
func (f *fakeRepo) status(id uuid.UUID) Status {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deployments[id].Status
}

func (f *fakeRepo) reason(id uuid.UUID) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.deployments[id].Reason
}

// fakeBus captures every Publish call in order.
type fakeBus struct {
	mu       sync.Mutex
	messages []fakeMsg
	failOn   map[string]error
}

type fakeMsg struct {
	Subject string
	Data    []byte
}

func newFakeBus() *fakeBus {
	return &fakeBus{failOn: make(map[string]error)}
}

func (b *fakeBus) Publish(subject string, data []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err, ok := b.failOn[subject]; ok {
		return err
	}
	b.messages = append(b.messages, fakeMsg{Subject: subject, Data: append([]byte(nil), data...)})
	return nil
}

func (b *fakeBus) subjects() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make([]string, 0, len(b.messages))
	for _, m := range b.messages {
		out = append(out, m.Subject)
	}
	return out
}

func (b *fakeBus) count() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.messages)
}

// fakeProfiles satisfies ProfileLoader — returns a canned profile every time.
type fakeProfiles struct {
	profile *profiles.Profile
	err     error
}

func (f *fakeProfiles) FindByID(_ context.Context, tenantID, id uuid.UUID) (*profiles.Profile, error) {
	if f.err != nil {
		return nil, f.err
	}
	p := *f.profile
	p.TenantID = tenantID
	p.ID = id
	return &p, nil
}

// -----------------------------------------------------------------------------
// Test helpers
// -----------------------------------------------------------------------------

// setup returns a fresh engine + fakes with a seed profile already installed.
func setup(t *testing.T) (*Engine, *fakeRepo, *fakeBus, *fakeProfiles) {
	t.Helper()
	repo := newFakeRepo()
	bus := newFakeBus()
	profs := &fakeProfiles{
		profile: &profiles.Profile{
			Version:          "v1",
			YAMLContent:      "metadata:\n  name: p\n  version: v1\n",
			SignatureEd25519: []byte("ed"),
			SignatureMLDSA:   []byte("ml"),
		},
	}
	e := newEngineWithRepo(repo, bus, profs)
	return e, repo, bus, profs
}

// waitForStatus blocks until fakeRepo reports the given status for id or the
// deadline elapses. Used by timer-driven tests where the transition is
// asynchronous relative to the Run goroutine.
func waitForStatus(t *testing.T, repo *fakeRepo, id uuid.UUID, want Status, within time.Duration) {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if repo.status(id) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("deployment %s did not reach status %s within %s (got %s)", id, want, within, repo.status(id))
}

func sampleSpec(canary uuid.UUID, rest ...uuid.UUID) DeploymentSpec {
	targets := append([]uuid.UUID{canary}, rest...)
	return DeploymentSpec{
		TenantID:                 uuid.New(),
		ProfileID:                uuid.New(),
		TargetDeviceIDs:          targets,
		CanaryDeviceID:           canary,
		ValidationMode:           ModeManual,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	}
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

func TestEngine_Create_PushesCanaryAndTransitionsToCanaryRunning(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	d1 := uuid.New()
	d2 := uuid.New()
	spec := sampleSpec(canary, d1, d2)

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.Status != StatusCanaryRunning {
		t.Fatalf("want status %s, got %s", StatusCanaryRunning, d.Status)
	}
	if got := bus.count(); got != 1 {
		t.Fatalf("want 1 publish, got %d", got)
	}
	wantSubject := "fleet.agent." + canary.String() + ".commands"
	if bus.subjects()[0] != wantSubject {
		t.Fatalf("want subject %s, got %s", wantSubject, bus.subjects()[0])
	}
	// Canary result should be recorded as applying.
	rs, _ := repo.ListResults(context.Background(), spec.TenantID, d.ID)
	if len(rs) != 1 || rs[0].Status != ResultApplying || !rs[0].IsCanary {
		t.Fatalf("want 1 applying canary result, got %+v", rs)
	}
}

func TestEngine_Create_CanaryPushFailed_StatusCanaryFailed(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	bus.failOn["fleet.agent."+canary.String()+".commands"] = errors.New("nats down")

	d, err := e.Create(context.Background(), sampleSpec(canary, uuid.New()))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if d.Status != StatusCanaryFailed {
		t.Fatalf("want %s, got %s", StatusCanaryFailed, d.Status)
	}
	if repo.status(d.ID) != StatusCanaryFailed {
		t.Fatalf("repo status: want %s, got %s", StatusCanaryFailed, repo.status(d.ID))
	}
}

func TestEngine_Canary_SuccessManualMode_TransitionsToAwaitingValidation(t *testing.T) {
	e, repo, _, _ := setup(t)
	canary := uuid.New()
	d, err := e.Create(context.Background(), sampleSpec(canary, uuid.New()))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	e.handle(context.Background(), DeviceResult{
		DeploymentID: d.ID, DeviceID: canary, Success: true,
	})

	if repo.status(d.ID) != StatusAwaitingValidation {
		t.Fatalf("want %s, got %s", StatusAwaitingValidation, repo.status(d.ID))
	}
}

func TestEngine_Canary_SuccessAutoMode_TransitionsToRollingOutAndPushesRollout(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	d1, d2 := uuid.New(), uuid.New()
	spec := sampleSpec(canary, d1, d2)
	spec.ValidationMode = ModeAuto

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Canary publish (1) recorded during Create; now drive canary success.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true})

	if repo.status(d.ID) != StatusRollingOut {
		t.Fatalf("want %s, got %s", StatusRollingOut, repo.status(d.ID))
	}
	// 1 canary + 2 rollout = 3 publishes total.
	if got := bus.count(); got != 3 {
		t.Fatalf("want 3 publishes, got %d (%v)", got, bus.subjects())
	}
}

func TestEngine_Canary_Failure_TransitionsToRolledBack_NoRollout(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	d1 := uuid.New()
	spec := sampleSpec(canary, d1)

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	e.handle(context.Background(), DeviceResult{
		DeploymentID: d.ID, DeviceID: canary, Success: false, ErrorMessage: "apply failed",
	})

	if repo.status(d.ID) != StatusRolledBack {
		t.Fatalf("want %s, got %s", StatusRolledBack, repo.status(d.ID))
	}
	// Only the canary publish happened; no rollout push on d1.
	if got := bus.count(); got != 1 {
		t.Fatalf("want 1 publish (canary only), got %d (%v)", got, bus.subjects())
	}
	for _, s := range bus.subjects() {
		if s == "fleet.agent."+d1.String()+".commands" {
			t.Fatalf("unexpected rollout publish to %s", s)
		}
	}
}

func TestEngine_Validate_TransitionsToRollingOut(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	d1 := uuid.New()
	d, err := e.Create(context.Background(), sampleSpec(canary, d1))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Canary succeeded, awaiting validation.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true})

	e.handle(context.Background(), Validate{DeploymentID: d.ID, ByUserID: uuid.New()})

	if repo.status(d.ID) != StatusRollingOut {
		t.Fatalf("want %s, got %s", StatusRollingOut, repo.status(d.ID))
	}
	// canary + 1 rollout push
	if got := bus.count(); got != 2 {
		t.Fatalf("want 2 publishes, got %d", got)
	}
}

func TestEngine_Rollout_AllSuccess_TransitionsToCompleted(t *testing.T) {
	e, repo, _, _ := setup(t)
	canary := uuid.New()
	d1, d2 := uuid.New(), uuid.New()
	spec := sampleSpec(canary, d1, d2)
	spec.ValidationMode = ModeAuto

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Canary OK drives rollout.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true})
	// Both rollout devices succeed.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: d1, Success: true})
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: d2, Success: true})

	if repo.status(d.ID) != StatusCompleted {
		t.Fatalf("want %s, got %s", StatusCompleted, repo.status(d.ID))
	}
}

func TestEngine_Rollout_AbortThresholdHit_TransitionsToPartiallyFailed(t *testing.T) {
	e, repo, _, _ := setup(t)
	canary := uuid.New()
	// 10 targets including canary; with 10% threshold, 1 failure trips.
	devs := []uuid.UUID{canary}
	for i := 0; i < 9; i++ {
		devs = append(devs, uuid.New())
	}
	spec := DeploymentSpec{
		TenantID:                 uuid.New(),
		ProfileID:                uuid.New(),
		TargetDeviceIDs:          devs,
		CanaryDeviceID:           canary,
		ValidationMode:           ModeAuto,
		ValidationTimeoutSeconds: 1800,
		FailureThresholdPct:      10,
	}

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Canary OK → rolling_out.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true})
	// One rollout failure = 10% of 10; crosses the 10% threshold while others
	// are still pending.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: devs[1], Success: false, ErrorMessage: "boom"})

	if repo.status(d.ID) != StatusPartiallyFailed {
		t.Fatalf("want %s, got %s", StatusPartiallyFailed, repo.status(d.ID))
	}
}

func TestEngine_ValidationTimeout_AutoValidates(t *testing.T) {
	e, repo, _, _ := setup(t)
	canary := uuid.New()
	d1 := uuid.New()
	spec := sampleSpec(canary, d1)
	spec.ValidationMode = ModeSemiAuto
	// 100ms so the test is quick but the timer path is exercised end-to-end.
	spec.ValidationTimeoutSeconds = 1

	// Start the engine goroutine so the timer's posted event is processed.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = e.Run(ctx)
		close(done)
	}()

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Drive canary success — the handler will arm the 1s timer.
	e.events <- DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true}

	// Engine arms timer, timer fires ~1s later, timeout posts ValidationTimeout
	// → rolling_out.
	waitForStatus(t, repo, d.ID, StatusRollingOut, 3*time.Second)

	cancel()
	<-done
}

func TestEngine_Rollback_PushesRollbackToSuccessDevices(t *testing.T) {
	e, repo, bus, _ := setup(t)
	canary := uuid.New()
	d1, d2, d3 := uuid.New(), uuid.New(), uuid.New()
	spec := sampleSpec(canary, d1, d2, d3)
	spec.ValidationMode = ModeAuto
	// Make the threshold high enough that 1 failure out of 4 won't flip the
	// deployment to partially_failed — we want it still in rolling_out when
	// the operator requests rollback, so the rollback handler runs.
	spec.FailureThresholdPct = 80

	d, err := e.Create(context.Background(), spec)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	// Canary OK → rolling_out, rollout pushes arrive.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: canary, Success: true})
	// d1 succeeded, d2 failed; d3 still applying.
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: d1, Success: true})
	e.handle(context.Background(), DeviceResult{DeploymentID: d.ID, DeviceID: d2, Success: false, ErrorMessage: "no"})

	if got := repo.status(d.ID); got != StatusRollingOut {
		t.Fatalf("precondition: want %s before rollback, got %s", StatusRollingOut, got)
	}

	countBeforeRollback := bus.count()

	e.handle(context.Background(), Rollback{DeploymentID: d.ID, Reason: "operator decision"})

	if repo.status(d.ID) != StatusRolledBack {
		t.Fatalf("want %s, got %s", StatusRolledBack, repo.status(d.ID))
	}
	// Rollback publishes only to devices with success/applying results:
	// canary (success) + d1 (success) + d3 (still applying) → 3 rollback publishes.
	// d2 was already failed so no rollback is pushed there.
	delta := bus.count() - countBeforeRollback
	if delta != 3 {
		t.Fatalf("want 3 rollback publishes, got %d (subjects=%v)", delta, bus.subjects())
	}
	if repo.reason(d.ID) != "operator decision" {
		t.Fatalf("want reason 'operator decision', got %q", repo.reason(d.ID))
	}
}

func TestEngine_Create_ValidationErrors(t *testing.T) {
	e, _, _, _ := setup(t)
	// Missing canary.
	if _, err := e.Create(context.Background(), DeploymentSpec{
		TenantID:  uuid.New(),
		ProfileID: uuid.New(),
		TargetDeviceIDs: []uuid.UUID{uuid.New()},
	}); err == nil {
		t.Fatal("expected error for missing canary_device_id")
	}
	// Missing targets.
	if _, err := e.Create(context.Background(), DeploymentSpec{
		TenantID:       uuid.New(),
		ProfileID:      uuid.New(),
		CanaryDeviceID: uuid.New(),
	}); err == nil {
		t.Fatal("expected error for missing target_device_ids")
	}
	// Canary not in targets.
	if _, err := e.Create(context.Background(), DeploymentSpec{
		TenantID:        uuid.New(),
		ProfileID:       uuid.New(),
		CanaryDeviceID:  uuid.New(),
		TargetDeviceIDs: []uuid.UUID{uuid.New()},
	}); err == nil {
		t.Fatal("expected error for canary not in target_device_ids")
	}
}
