package integrity

import "testing"

func TestCheckKernelThreadForgery(t *testing.T) {
	tests := []struct {
		name     string
		proc     ProcessInfo
		wantForg bool
		desc     string
	}{
		{
			name:     "genuine kworker",
			proc:     ProcessInfo{PID: 100, Name: "kworker/0:0-events", PPID: 2, Path: ""},
			wantForg: false,
			desc:     "real kernel thread: PPID=2, no exe",
		},
		{
			name:     "forged kworker — PPID mismatch",
			proc:     ProcessInfo{PID: 5000, Name: "kworker/0:0-events", PPID: 42, Path: "/tmp/payload"},
			wantForg: true,
			desc:     "attacker: comm looks like kernel thread but PPID=42",
		},
		{
			name:     "forged kworker — child of init",
			proc:     ProcessInfo{PID: 5001, Name: "kworker/1:1H", PPID: 1, Path: "/bin/malware"},
			wantForg: true,
			desc:     "attacker: reparented to init, comm=kworker",
		},
		{
			name:     "forged ksoftirqd",
			proc:     ProcessInfo{PID: 5002, Name: "ksoftirqd/0", PPID: 1337, Path: "/tmp/hide"},
			wantForg: true,
			desc:     "attacker: comm=ksoftirqd but PPID!=2, exe exists",
		},
		{
			name:     "forged kthreadd",
			proc:     ProcessInfo{PID: 5003, Name: "kthreadd", PPID: 1, Path: ""},
			wantForg: true,
			desc:     "attacker: comm=kthreadd but PPID=1 (not 2)",
		},
		{
			name:     "legitimate user process",
			proc:     ProcessInfo{PID: 2000, Name: "bash", PPID: 1500, Path: "/usr/bin/bash"},
			wantForg: false,
			desc:     "normal bash — not a kernel thread pattern",
		},
		{
			name:     "nginx — non-matching",
			proc:     ProcessInfo{PID: 3000, Name: "nginx", PPID: 1, Path: "/usr/sbin/nginx"},
			wantForg: false,
			desc:     "normal service — comm doesn't match kernel pattern",
		},
		{
			name:     "forged migration thread",
			proc:     ProcessInfo{PID: 5004, Name: "migration/0", PPID: 100, Path: "/dev/shm/.x"},
			wantForg: true,
			desc:     "attacker: comm=migration/0 but PPID=100",
		},
		{
			name:     "forged watchdog",
			proc:     ProcessInfo{PID: 5005, Name: "watchdogd", PPID: 7777, Path: "/tmp/w"},
			wantForg: true,
			desc:     "attacker: comm=watchdogd but PPID=7777",
		},
		{
			name:     "genuine rcu kernel thread",
			proc:     ProcessInfo{PID: 13, Name: "rcu_preempt", PPID: 2, Path: ""},
			wantForg: false,
			desc:     "real kernel thread: rcu_preempt with PPID=2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckKernelThreadForgery(tt.proc)
			if result.Forged != tt.wantForg {
				t.Errorf("%s: CheckKernelThreadForgery(%+v) = %v (reason=%q), want %v",
					tt.desc, tt.proc, result.Forged, result.Reason, tt.wantForg)
			}
		})
	}
}

func TestKernelThreadProcess(t *testing.T) {
	tests := []struct {
		name     string
		proc     ProcessInfo
		wantTrue bool
	}{
		{name: "real kernel thread", proc: ProcessInfo{PID: 10, Name: "kworker/0:0", PPID: 2, Path: "", Cmdline: ""}, wantTrue: true},
		{name: "wrong PPID", proc: ProcessInfo{PID: 10, Name: "kworker/0:0", PPID: 1, Path: "", Cmdline: ""}, wantTrue: false},
		{name: "has exe", proc: ProcessInfo{PID: 10, Name: "kworker/0:0", PPID: 2, Path: "/tmp/x", Cmdline: ""}, wantTrue: false},
		{name: "has cmdline", proc: ProcessInfo{PID: 10, Name: "kworker/0:0", PPID: 2, Path: "", Cmdline: "-bash"}, wantTrue: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := KernelThreadProcess(tt.proc); got != tt.wantTrue {
				t.Errorf("KernelThreadProcess(%+v) = %v, want %v", tt.proc, got, tt.wantTrue)
			}
		})
	}
}

func TestCheckBPFForgeryTag(t *testing.T) {
	if CheckBPFForgeryTag(0x464F5247) != true {
		t.Error("FORG tag not detected")
	}
	if CheckBPFForgeryTag(0x00000000) != false {
		t.Error("zero value incorrectly flagged as FORG")
	}
	if CheckBPFForgeryTag(0x12345678) != false {
		t.Error("random value incorrectly flagged as FORG")
	}
}
