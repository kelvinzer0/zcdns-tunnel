package utils

func IsHTTPRequestFast(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	// State machine for HTTP detection
	state := 0
	httpFound := false

	for i, b := range data {
		switch state {
		case 0: // Looking for method
			if b == 'G' && i+3 < len(data) &&
				data[i+1] == 'E' && data[i+2] == 'T' && data[i+3] == ' ' {
				state = 1
				i += 3
			} else if b == 'P' && i+4 < len(data) &&
				data[i+1] == 'O' && data[i+2] == 'S' && data[i+3] == 'T' && data[i+4] == ' ' {
				state = 1
				i += 4
			} else if b == 'P' && i+3 < len(data) &&
				data[i+1] == 'U' && data[i+2] == 'T' && data[i+3] == ' ' {
				state = 1
				i += 3
			}
			// Add other methods as needed
		case 1: // Looking for HTTP version
			if b == 'H' && i+8 < len(data) &&
				data[i+1] == 'T' && data[i+2] == 'T' && data[i+3] == 'P' &&
				data[i+4] == '/' && data[i+5] == '1' && data[i+6] == '.' {
				httpFound = true
				break
			}
		}
		if httpFound {
			break
		}
	}

	return httpFound
}
