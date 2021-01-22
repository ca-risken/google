package common

// CutString returns cutting specific `cut` characters with ` ...` suffix from `input` string.
func CutString(input string, cut int) string {
	if len(input) > cut {
		return input[:cut] + " ..." // cut long text
	}
	return input
}
