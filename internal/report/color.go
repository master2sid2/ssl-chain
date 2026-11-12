package report

// painter wraps text in ANSI colour codes, or leaves it alone when off.
type painter struct{ on bool }

func (p painter) paint(code, s string) string {
	if !p.on {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func (p painter) good(s string) string  { return p.paint("32", s) }
func (p painter) bad(s string) string   { return p.paint("31", s) }
func (p painter) warn(s string) string  { return p.paint("33", s) }
func (p painter) dim(s string) string   { return p.paint("2", s) }
func (p painter) bold(s string) string  { return p.paint("1", s) }
func (p painter) white(s string) string { return p.paint("1;97", s) }
func (p painter) plain(s string) string { return p.paint("97", s) }
func (p painter) cyan(s string) string  { return p.paint("1;36", s) }

func (p painter) goodBold(s string) string { return p.paint("1;32", s) }
func (p painter) badBold(s string) string  { return p.paint("1;31", s) }
