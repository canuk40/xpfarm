package utils

import (
	"strconv"
)

// StringToInt converts a string to an int, returning -1 on error
// to distinguish from a valid port 0.
func StringToInt(s string) int {
	i, err := strconv.Atoi(s)
	if err != nil {
		return -1
	}
	return i
}
