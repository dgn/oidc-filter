package main

import "strings"

func trim(input string) string {
	whitespaces := "\n\t "
	ret := ""
	index := 0
	// first loop: until first non-whitespace char
	for _, c := range input {
		index++
		ignore := strings.ContainsRune(whitespaces, c)
		if !ignore {
			ret += string(c)
			break
		}
	}
	if index == len(input) {
		return ret
	}
	copy := ret
	// second loop: until the end
	for _, c := range input[index:] {
		index++
		copy += string(c)
		ignore := strings.ContainsRune(whitespaces, c)
		// if non-ws rune is found, use the copy and start from scratch
		if !ignore {
			ret = copy
		}
	}
	return ret
}
