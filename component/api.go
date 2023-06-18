//go:build api || full
// +build api full

package build

import (
	_ "github.com/faireal/trojan-go/api/control"
	_ "github.com/faireal/trojan-go/api/service"
)
