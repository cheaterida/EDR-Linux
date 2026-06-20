package procutil

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

func StartTicksFromStat(statLine string) string {
	if statLine == "" {
		return ""
	}
	idx := strings.LastIndex(statLine, ")")
	if idx == -1 || idx+2 >= len(statLine) {
		return ""
	}
	fields := strings.Fields(statLine[idx+2:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

func UserFromPID(pid int) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/loginuid", pid))
	if err != nil {
		return ""
	}
	uid, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 32)
	if err != nil || uid < 0 {
		return ""
	}
	u, err := user.LookupId(strconv.FormatInt(uid, 10))
	if err != nil {
		return ""
	}
	return u.Username
}
