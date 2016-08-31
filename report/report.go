// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

type oops struct {
	header  []byte
	formats []oopsFormat
}

type oopsFormat struct {
	re  *regexp.Regexp
	fmt string
}

var oopses = []*oops{
	&oops{
		[]byte("BUG:"),
		[]oopsFormat{
			{
				compile("BUG: KASAN: ([a-z\\-]+) in {{FUNC}}(?:.*\\n)+.*(Read|Write) of size ([0-9]+)"),
				"KASAN: %[1]v %[3]v of size %[4]v in %[2]v",
			},
			{
				compile("BUG: KASAN: ([a-z\\-]+) on address(?:.*\\n)+.*(Read|Write) of size ([0-9]+)"),
				"KASAN: %[1]v %[2]v of size %[3]v",
			},
			{
				compile("BUG: unable to handle kernel paging request(?:.*\\n)+.*IP: {{PC}} +{{FUNC}}"),
				"BUG: unable to handle kernel paging request in %[1]v",
			},
			{
				compile("BUG: unable to handle kernel NULL pointer dereference(?:.*\\n)+.*IP: {{PC}} +{{FUNC}}"),
				"BUG: unable to handle kernel NULL pointer dereference in %[1]v",
			},
		},
	},
	&oops{
		[]byte("WARNING:"),
		[]oopsFormat{
			{
				compile("WARNING: .* at [a-zA-Z0-9_/.]+:[0-9]+ {{FUNC}}"),
				"WARNING in %[1]v",
			},
		},
	},
	&oops{
		[]byte("INFO:"),
		[]oopsFormat{
			{
				compile("INFO: possible circular locking dependency detected \\](?:.*\\n)+.*is trying to acquire lock(?:.*\\n)+.*at: {{PC}} +{{FUNC}}"),
				"possible deadlock in %[1]v",
			},
		},
	},
	&oops{
		[]byte("Unable to handle kernel paging request"),
		[]oopsFormat{
			{
				compile("Unable to handle kernel paging request(?:.*\\n)+.*PC is at {{FUNC}}"),
				"unable to handle kernel paging request in %[1]v",
			},
		},
	},
	&oops{
		[]byte("general protection fault:"),
		[]oopsFormat{
			{
				compile("general protection fault:(?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"general protection fault in %[1]v",
			},
		},
	},
	&oops{
		[]byte("Kernel panic"),
		[]oopsFormat{
			{
				compile("Kernel panic - not syncing: Attempted to kill init!"),
				"kernel panic: Attempted to kill init!",
			},
			{
				compile("Kernel panic - not syncing: (.*)"),
				"kernel panic: %[1]v",
			},
		},
	},
	&oops{
		[]byte("kernel BUG"),
		[]oopsFormat{
			{
				compile("kernel BUG (.*)"),
				"kernel BUG %[1]v",
			},
		},
	},
	&oops{
		[]byte("Kernel BUG"),
		[]oopsFormat{
			{
				compile("Kernel BUG (.*)"),
				"kernel BUG %[1]v",
			},
		},
	},
	&oops{
		[]byte("divide error:"),
		[]oopsFormat{
			{
				compile("divide error: (?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"divide error in %[1]v",
			},
		},
	},
	&oops{
		[]byte("invalid opcode:"),
		[]oopsFormat{
			{
				compile("invalid opcode: (?:.*\n)+.*RIP: [0-9]+:{{PC}} +{{PC}} +{{FUNC}}"),
				"invalid opcode in %[1]v",
			},
		},
	},
	&oops{
		[]byte("unreferenced object"),
		[]oopsFormat{
			{
				compile("unreferenced object {{ADDR}} \\(size ([0-9]+)\\):(?:.*\n.*)+backtrace:.*\n.*{{PC}}.*\n.*{{PC}}.*\n.*{{PC}} {{FUNC}}"),
				"memory leak in %[2]v (size %[1]v)",
			},
		},
	},
	&oops{
		[]byte("UBSAN:"),
		[]oopsFormat{},
	},
}

var consoleOutputRe = regexp.MustCompile("^\\[ *[0-9]+\\.[0-9]+\\] ")

func compile(re string) *regexp.Regexp {
	re = strings.Replace(re, "{{ADDR}}", "0x[0-9a-f]+", -1)
	re = strings.Replace(re, "{{PC}}", "\\[\\<[0-9a-z]+\\>\\]", -1)
	re = strings.Replace(re, "{{FUNC}}", "([a-zA-Z0-9_]+)(?:\\.(?:constprop|isra)\\.[0-9]+)?\\+", -1)
	return regexp.MustCompile(re)
}

// ContainsCrash searches kernel console output for oops messages.
func ContainsCrash(output []byte) bool {
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops := range oopses {
			match := bytes.Index(output[pos:next], oops.header)
			if match == -1 {
				continue
			}
			return true
		}
		pos = next + 1
	}
	return false
}

// Parse extracts information about oops from console output.
// Desc contains a representative description of the first oops (empty if no oops found),
// text contains whole oops text,
// start and end denote region of output with oops message(s).
func Parse(output []byte) (desc, text string, start int, end int) {
	var oops *oops
	var textData []byte
	for pos := 0; pos < len(output); {
		next := bytes.IndexByte(output[pos:], '\n')
		if next != -1 {
			next += pos
		} else {
			next = len(output)
		}
		for _, oops1 := range oopses {
			match := bytes.Index(output[pos:next], oops1.header)
			if match == -1 {
				continue
			}
			if oops == nil {
				oops = oops1
				start = pos
				desc = string(output[pos+match : next])
			}
			end = next
		}
		if oops != nil {
			if consoleOutputRe.Match(output[pos:next]) {
				lineStart := bytes.Index(output[pos:next], []byte("] ")) + pos + 2
				lineEnd := next
				if lineEnd != 0 && output[lineEnd-1] == '\r' {
					lineEnd--
				}
				textData = append(textData, output[lineStart:lineEnd]...)
				textData = append(textData, '\n')
			}
		}
		pos = next + 1
	}
	if oops == nil {
		return
	}
	text = string(textData)
	desc = extractDescription(output[start:], oops)
	if len(desc) > 0 && desc[len(desc)-1] == '\r' {
		desc = desc[:len(desc)-1]
	}
	return
}

func extractDescription(output []byte, oops *oops) string {
	for _, format := range oops.formats {
		match := format.re.FindSubmatch(output)
		if match == nil {
			continue
		}
		var args []interface{}
		for i := 1; i < len(match); i++ {
			args = append(args, string(match[i]))
		}
		return fmt.Sprintf(format.fmt, args...)
	}
	pos := bytes.Index(output, oops.header)
	if pos == -1 {
		panic("non matching oops")
	}
	end := bytes.IndexByte(output[pos:], '\n')
	if end == -1 {
		end = len(output)
	} else {
		end += pos
	}
	return string(output[pos:end])
}