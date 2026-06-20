package response

import (
	"strings"
	"testing"
)

func TestNFTProviderDryRun(t *testing.T) {
	res := NFTProvider{DryRun: true, Table: "edr", Chain: "blocklist"}.ApplyBlock(ActionRequest{Action: "nft_block", Protocol: "tcp", LocalPort: 4444, RemoteAddr: "203.0.113.66"})
	if !res.Success || !strings.Contains(res.Detail, "nft dry-run") || !strings.Contains(res.Detail, "203.0.113.66") {
		t.Fatalf("unexpected result: %#v", res)
	}
}
