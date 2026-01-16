//go:build !netgo

package buildtags

// This variable is used to satisfy the IDE and compilation without tags.
// However, the project should be compiled with `-tags netgo` for production.
var NETGO = false
