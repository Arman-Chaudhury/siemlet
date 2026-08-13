package parse

import (
	"testing"
	"time"
)

func TestLine(t *testing.T) {
	loc := time.UTC
	tests := []struct {
		name string
		line string
		want Event
	}{
		{
			name: "failed password",
			line: "Aug 13 22:41:07 web-01 sshd[1234]: Failed password for root from 203.0.113.7 port 52144 ssh2",
			want: Event{Host: "web-01", Program: "sshd", PID: 1234, Kind: AuthFail,
				User: "root", IP: "203.0.113.7", Port: 52144},
		},
		{
			name: "failed password invalid user",
			line: "Aug 13 22:41:09 web-01 sshd[1240]: Failed password for invalid user admin from 203.0.113.7 port 52150 ssh2",
			want: Event{Host: "web-01", Program: "sshd", PID: 1240, Kind: InvalidUser,
				User: "admin", IP: "203.0.113.7", Port: 52150},
		},
		{
			name: "accepted publickey",
			line: "Aug 13 22:45:00 web-01 sshd[1300]: Accepted publickey for arman from 198.51.100.3 port 60022 ssh2",
			want: Event{Host: "web-01", Program: "sshd", PID: 1300, Kind: AuthSuccess,
				User: "arman", IP: "198.51.100.3", Port: 60022},
		},
		{
			name: "single-digit day double space",
			line: "Aug  3 01:02:03 db-01 sshd[99]: Invalid user oracle from 192.0.2.10 port 41000",
			want: Event{Host: "db-01", Program: "sshd", PID: 99, Kind: InvalidUser,
				User: "oracle", IP: "192.0.2.10", Port: 41000},
		},
		{
			name: "pam auth failure",
			line: "Aug 13 22:41:20 web-01 sshd[1250]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=203.0.113.7  user=root",
			want: Event{Host: "web-01", Program: "sshd", PID: 1250, Kind: AuthFail,
				User: "root", IP: "203.0.113.7"},
		},
		{
			name: "sudo command",
			line: "Aug 13 23:00:01 web-01 sudo:    arman : TTY=pts/0 ; PWD=/home/arman ; USER=root ; COMMAND=/usr/bin/apt update",
			want: Event{Host: "web-01", Program: "sudo", Kind: SudoCommand,
				User: "arman", Detail: "/usr/bin/apt update"},
		},
		{
			name: "useradd",
			line: "Aug 13 23:05:00 web-01 useradd[2001]: new user: name=backdoor, UID=1001, GID=1001, home=/home/backdoor, shell=/bin/bash",
			want: Event{Host: "web-01", Program: "useradd", PID: 2001, Kind: UserAdded,
				User: "backdoor"},
		},
		{
			name: "unclassified body",
			line: "Aug 13 23:10:00 web-01 systemd[1]: Started Session 42 of user arman.",
			want: Event{Host: "web-01", Program: "systemd", PID: 1, Kind: Other},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Line(tc.line, 2026, loc)
			if err != nil {
				t.Fatalf("Line() error: %v", err)
			}
			if got.Time.Year() != 2026 {
				t.Errorf("year = %d, want 2026", got.Time.Year())
			}
			if got.Host != tc.want.Host || got.Program != tc.want.Program ||
				got.PID != tc.want.PID || got.Kind != tc.want.Kind ||
				got.User != tc.want.User || got.IP != tc.want.IP ||
				got.Port != tc.want.Port || got.Detail != tc.want.Detail {
				t.Errorf("Line() = %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestLineRejectsNonSyslog(t *testing.T) {
	if _, err := Line("not a log line", 2026, time.UTC); err == nil {
		t.Fatal("expected error for non-syslog line")
	}
}
