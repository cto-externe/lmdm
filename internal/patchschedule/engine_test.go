// SPDX-License-Identifier: EUPL-1.2
// SPDX-FileCopyrightText: 2026 CTO Externe

package patchschedule

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"

	lmdmv1 "github.com/cto-externe/lmdm/gen/go/lmdm/v1"
)

// ---------------------------------------------------------------------------
// In-memory fakes
// ---------------------------------------------------------------------------

type fakeRepo struct {
	due    []Schedule
	marked []markedCall
	err    error
}

type markedCall struct {
	id       uuid.UUID
	ranAt    time.Time
	status   string
	nextFire time.Time
	skipped  bool
}

func (r *fakeRepo) FindDue(_ context.Context, _ time.Time) ([]Schedule, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.due, nil
}

func (r *fakeRepo) MarkRan(_ context.Context, id uuid.UUID, ranAt time.Time, status string, nextFire time.Time, skipped bool) error {
	r.marked = append(r.marked, markedCall{id: id, ranAt: ranAt, status: status, nextFire: nextFire, skipped: skipped})
	return nil
}

type publishCall struct {
	subject string
	data    []byte
}

type fakePublisher struct {
	calls []publishCall
	err   error
}

func (p *fakePublisher) Publish(subject string, data []byte) error {
	if p.err != nil {
		return p.err
	}
	p.calls = append(p.calls, publishCall{subject: subject, data: data})
	return nil
}

type fakeResolver struct {
	policy *ResolvedPolicy
	err    error
}

func (r *fakeResolver) Resolve(_ context.Context, _ uuid.UUID) (*ResolvedPolicy, error) {
	if r.err != nil {
		return nil, r.err
	}
	return r.policy, nil
}

type fakeDeviceLister struct {
	ids []uuid.UUID
	err error
}

func (d *fakeDeviceLister) ListTenantDeviceIDs(_ context.Context, _ uuid.UUID) ([]uuid.UUID, error) {
	if d.err != nil {
		return nil, d.err
	}
	return d.ids, nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestEngine_FiresDueSchedule_PublishesCommand: device-specific schedule fires,
// one Publish call on the correct subject, MarkRan called with RunStatusOK.
func TestEngine_FiresDueSchedule_PublishesCommand(t *testing.T) {
	dev := uuid.New()
	ten := uuid.New()
	now := time.Date(2026, 4, 21, 22, 0, 0, 0, time.UTC)
	repo := &fakeRepo{due: []Schedule{{
		ID: uuid.New(), TenantID: ten, DeviceID: &dev,
		CronExpr: "0 22 * * *", NextFireAt: now.Add(-time.Minute),
		Enabled: true,
	}}}
	pub := &fakePublisher{}
	res := &fakeResolver{policy: &ResolvedPolicy{RebootPolicy: RebootPolicyImmediateAfterApply}}
	e := newEngine(repo, pub, res, nil, time.Minute, func() time.Time { return now })

	if err := e.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("got %d Publish calls, want 1", len(pub.calls))
	}
	wantSubject := "fleet.agent." + dev.String() + ".commands"
	if pub.calls[0].subject != wantSubject {
		t.Errorf("subject = %q, want %q", pub.calls[0].subject, wantSubject)
	}
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(pub.calls[0].data, &env); err != nil {
		t.Fatal(err)
	}
	ap := env.GetApplyPatches()
	if ap == nil {
		t.Fatal("expected ApplyPatches variant")
	}
	if ap.RebootPolicy != RebootPolicyImmediateAfterApply {
		t.Errorf("reboot_policy = %q, want %q", ap.RebootPolicy, RebootPolicyImmediateAfterApply)
	}
	if len(repo.marked) != 1 || repo.marked[0].status != RunStatusOK {
		t.Errorf("MarkRan not called with OK: %+v", repo.marked)
	}
	if repo.marked[0].skipped {
		t.Errorf("skipped should be false for successful run")
	}
}

// TestEngine_SkipsMissedWindow_SetsStatus: schedule overdue by 25h is skipped.
func TestEngine_SkipsMissedWindow_SetsStatus(t *testing.T) {
	dev := uuid.New()
	ten := uuid.New()
	now := time.Date(2026, 4, 22, 10, 0, 0, 0, time.UTC)
	// next_fire_at was 25h ago — beyond MissedWindowThreshold (24h)
	repo := &fakeRepo{due: []Schedule{{
		ID: uuid.New(), TenantID: ten, DeviceID: &dev,
		CronExpr:   "0 9 * * *",
		NextFireAt: now.Add(-25 * time.Hour),
		Enabled:    true,
	}}}
	pub := &fakePublisher{}
	res := &fakeResolver{policy: &ResolvedPolicy{RebootPolicy: RebootPolicyAdminOnly}}
	e := newEngine(repo, pub, res, nil, time.Minute, func() time.Time { return now })

	if err := e.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.calls) != 0 {
		t.Errorf("expected no Publish calls, got %d", len(pub.calls))
	}
	if len(repo.marked) != 1 {
		t.Fatalf("expected 1 MarkRan call, got %d", len(repo.marked))
	}
	m := repo.marked[0]
	if m.status != RunStatusSkippedMissedWindow {
		t.Errorf("status = %q, want %q", m.status, RunStatusSkippedMissedWindow)
	}
	if !m.skipped {
		t.Errorf("skipped should be true for missed window")
	}
	if m.nextFire.IsZero() {
		t.Errorf("nextFire should be non-zero")
	}
}

// TestEngine_TenantWideSchedule_PublishesPerDevice: nil DeviceID → one command per device.
func TestEngine_TenantWideSchedule_PublishesPerDevice(t *testing.T) {
	ten := uuid.New()
	devs := []uuid.UUID{uuid.New(), uuid.New(), uuid.New()}
	now := time.Date(2026, 4, 22, 3, 0, 0, 0, time.UTC)
	repo := &fakeRepo{due: []Schedule{{
		ID:         uuid.New(),
		TenantID:   ten,
		DeviceID:   nil, // tenant-wide
		CronExpr:   "0 3 * * *",
		NextFireAt: now.Add(-time.Minute),
		Enabled:    true,
	}}}
	pub := &fakePublisher{}
	res := &fakeResolver{policy: &ResolvedPolicy{RebootPolicy: RebootPolicyNextMaintenanceWindow}}
	lister := &fakeDeviceLister{ids: devs}
	e := newEngine(repo, pub, res, lister, time.Minute, func() time.Time { return now })

	if err := e.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.calls) != 3 {
		t.Fatalf("got %d Publish calls, want 3", len(pub.calls))
	}
	for i, call := range pub.calls {
		want := "fleet.agent." + devs[i].String() + ".commands"
		if call.subject != want {
			t.Errorf("call[%d] subject = %q, want %q", i, call.subject, want)
		}
	}
	if len(repo.marked) != 1 || repo.marked[0].status != RunStatusOK {
		t.Errorf("MarkRan not called with OK: %+v", repo.marked)
	}
}

// TestEngine_BadCronExpr_MarksError: unparseable cron expression → publish_error, no Publish.
func TestEngine_BadCronExpr_MarksError(t *testing.T) {
	dev := uuid.New()
	ten := uuid.New()
	now := time.Date(2026, 4, 22, 12, 0, 0, 0, time.UTC)
	repo := &fakeRepo{due: []Schedule{{
		ID: uuid.New(), TenantID: ten, DeviceID: &dev,
		CronExpr:   "not-a-cron",
		NextFireAt: now.Add(-time.Minute),
		Enabled:    true,
	}}}
	pub := &fakePublisher{}
	res := &fakeResolver{policy: &ResolvedPolicy{RebootPolicy: RebootPolicyAdminOnly}}
	e := newEngine(repo, pub, res, nil, time.Minute, func() time.Time { return now })

	if err := e.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.calls) != 0 {
		t.Errorf("expected no Publish calls, got %d", len(pub.calls))
	}
	if len(repo.marked) != 1 {
		t.Fatalf("expected 1 MarkRan call, got %d", len(repo.marked))
	}
	if repo.marked[0].status != RunStatusPublishError {
		t.Errorf("status = %q, want %q", repo.marked[0].status, RunStatusPublishError)
	}
	if repo.marked[0].skipped {
		t.Errorf("skipped should be false for parse error")
	}
}

// TestEngine_PerDeviceSchedule_ResolvesOverride: device-specific schedule uses resolved policy.
func TestEngine_PerDeviceSchedule_ResolvesOverride(t *testing.T) {
	dev := uuid.New()
	ten := uuid.New()
	now := time.Date(2026, 4, 22, 8, 0, 0, 0, time.UTC)
	repo := &fakeRepo{due: []Schedule{{
		ID: uuid.New(), TenantID: ten, DeviceID: &dev,
		CronExpr:   "0 8 * * *",
		NextFireAt: now.Add(-30 * time.Second),
		Enabled:    true,
	}}}
	pub := &fakePublisher{}
	// Resolver returns immediate_after_apply (device override scenario).
	res := &fakeResolver{policy: &ResolvedPolicy{RebootPolicy: RebootPolicyImmediateAfterApply}}
	e := newEngine(repo, pub, res, nil, time.Minute, func() time.Time { return now })

	if err := e.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(pub.calls) != 1 {
		t.Fatalf("got %d Publish calls, want 1", len(pub.calls))
	}
	var env lmdmv1.CommandEnvelope
	if err := proto.Unmarshal(pub.calls[0].data, &env); err != nil {
		t.Fatal(err)
	}
	ap := env.GetApplyPatches()
	if ap == nil {
		t.Fatal("expected ApplyPatches variant")
	}
	if ap.RebootPolicy != RebootPolicyImmediateAfterApply {
		t.Errorf("reboot_policy = %q, want %q", ap.RebootPolicy, RebootPolicyImmediateAfterApply)
	}
}
