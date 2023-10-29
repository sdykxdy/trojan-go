//go:build api || full
// +build api full

package build

import (
	_ "github.com/sdykxdy/trojan-go/api/control"
	_ "github.com/sdykxdy/trojan-go/api/service"
)
