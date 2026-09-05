package scrubber

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
)

type Finding struct {
	Type       string
	Span       [2]int
	Value      string
	Confidence float64
	Detector   string
}

type rule struct {
	typ   string
	re    *regexp.Regexp
	conf  float64
	valid func(string) bool
}

func mustRe(s string) *regexp.Regexp { return regexp.MustCompile(s) }

func luhn(s string) bool {
	digits := ""
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits += string(r)
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, alt := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := int(digits[i] - '0')
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

// validRU8 rejects 8xxxxxxxxxx that collide with card-like 16-digit runs.
func validRU8(s string) bool {
	n := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			n++
		}
	}
	return n == 11
}

func validINN12(s string) bool {
	d := digits(s)
	if len(d) != 12 {
		return false
	}
	c1 := [10]int{7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	c2 := [11]int{3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8}
	s1, s2 := 0, 0
	for i := range 10 {
		s1 += int(d[i]-'0') * c1[i]
	}
	for i := range 11 {
		s2 += int(d[i]-'0') * c2[i]
	}
	return int(d[10]-'0') == s1%11%10 && int(d[11]-'0') == s2%11%10
}

func rules() []rule {
	return []rule{
		{"EMAIL", mustRe(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`), 0.95, nil},
		{"PHONE_RU", mustRe(`\+7[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}`), 0.95, nil},
		{"PHONE_RU", mustRe(`\b8[\s\-]?\(?\d{3}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}\b`), 0.85, validRU8},
		{"PHONE", mustRe(`\+?[0-9][0-9\- ().]{7,}[0-9]`), 0.4, nil},
		{"CREDIT_CARD", mustRe(`\b(?:\d[ \-]?){13,19}\b`), 0.7, luhn},
		{"JWT", mustRe(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`), 0.95, nil},
		{"PEM", mustRe(`-----BEGIN [A-Z ]+PRIVATE KEY-----`), 0.99, nil},
		{"AWS_KEY", mustRe(`\bAKIA[0-9A-Z]{16}\b`), 0.99, nil},
		{"GITHUB_PAT", mustRe(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`), 0.99, nil},
		{"SLACK", mustRe(`\bxox[baprs]-[A-Za-z0-9\-]{8,}\b`), 0.99, nil},
		{"TELEGRAM", mustRe(`\b\d{6,}:[A-Za-z0-9_\-]{20,}\b`), 0.9, nil},
		{"STRIPE", mustRe(`\b[rs]k_(live|test)_[A-Za-z0-9]{8,}\b`), 0.99, nil},
		{"GOOGLE_API", mustRe(`\bAIza[0-9A-Za-z_\-]{20,}\b`), 0.99, nil},
		{"OPENAI_KEY", mustRe(`\bsk-(proj-)?[A-Za-z0-9]{16,}\b`), 0.95, nil},
		{"IPV4", mustRe(`\b(?:\d{1,3}\.){3}\d{1,3}\b`), 0.5, nil},
		{"PASSWORD_ASSIGN", mustRe(`(?i)(?:пароль|password|passwd|pwd|secret)\s*[:=]\s*\S+`), 0.85, nil},
		{"PERSON_FIO", mustRe(`\b[А-ЯЁ][а-яё]+\s+[А-ЯЁ]\.[А-ЯЁ]\.`), 0.8, nil},
		{"SNILS", mustRe(`\b\d{3}-\d{3}-\d{3}\s?\d{2}\b`), 0.9, validSNILS},
		{"INN_FL", mustRe(`\b\d{12}\b`), 0.55, validINN12},
		{"PASSPORT_RU", mustRe(`\b\d{4}\s?№?\s?\d{6}\b`), 0.7, nil},
		{"IBAN", mustRe(`\b[A-Z]{2}\d{2}[ ]?(?:[A-Za-z0-9]{4}[ ]?){2,7}[A-Za-z0-9]{1,4}\b`), 0.85, validIBAN},
		{"OMS", mustRe(`\b\d{16}\b`), 0.6, validOMS},
	}
}

func digits(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func validSNILS(s string) bool {
	d := digits(s)
	if len(d) != 11 {
		return false
	}
	sum := 0
	for i := 0; i < 9; i++ {
		sum += int(d[i]-'0') * (9 - i)
	}
	mod := sum % 101
	if mod == 100 {
		mod = 0
	}
	return int(d[9]-'0')*10+int(d[10]-'0') == mod
}

func validIBAN(s string) bool {
	c := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(s, " ", ""), "-", ""))
	if len(c) < 15 || len(c) > 34 {
		return false
	}
	for _, r := range c {
		if !(r >= '0' && r <= '9' || r >= 'A' && r <= 'Z') {
			return false
		}
	}
	// mod97: move first 4 chars to end, letters -> digits
	rot := c[4:] + c[:4]
	rem := 0
	for _, r := range rot {
		if r >= '0' && r <= '9' {
			rem = (rem*10 + int(r-'0')) % 97
		} else {
			v := int(r-'A') + 10
			rem = (rem*10 + v/10) % 97
			rem = (rem*10 + v%10) % 97
		}
	}
	return rem == 1
}

func validOMS(s string) bool {
	d := digits(s)
	if len(d) != 16 {
		return false
	}
	same := true
	for i := 1; i < 16; i++ {
		if d[i] != d[0] {
			same = false
			break
		}
	}
	return !same
}

// L3 contextual keywords for entropy detector (widened context)
var secretWords = []string{"token", "key", "secret", "password", "authorization", "passwd", "pwd", "apikey", "api_key", "auth", "bearer", "credential", "private", "client_secret", "access_token", "refresh_token", "session", "cookie", "пароль", "секрет", "токен", "ключ"}

// L4 compact name dictionaries (~100 ru + ~100 en common first names)
var ruFirstNames = map[string]bool{"александр": true, "алексей": true, "андрей": true, "анна": true, "артем": true, "борис": true, "вадим": true, "валентина": true, "валерий": true, "вера": true, "виктор": true, "владимир": true, "владислав": true, "галина": true, "георгий": true, "григорий": true, "даниил": true, "дарья": true, "денис": true, "дмитрий": true, "евгений": true, "евгения": true, "егор": true, "екатерина": true, "елена": true, "иван": true, "игорь": true, "инна": true, "ирина": true, "кирилл": true, "константин": true, "лариса": true, "леонид": true, "любовь": true, "людмила": true, "максим": true, "марина": true, "мария": true, "михаил": true, "надежда": true, "наталья": true, "наталия": true, "никита": true, "николай": true, "нина": true, "олег": true, "ольга": true, "павел": true, "петр": true, "роман": true, "светлана": true, "семен": true, "сергей": true, "софия": true, "софья": true, "станислав": true, "степан": true, "татьяна": true, "тимофей": true, "федор": true, "эдуард": true, "юлия": true, "юрий": true, "яна": true, "ярослав": true, "виталий": true, "владислава": true, "геннадий": true, "диана": true, "зара": true, "зоя": true, "инга": true, "карина": true, "кристина": true, "ксения": true, "лидия": true, "маргарита": true, "милана": true, "мирон": true, "назар": true, "оксана": true, "полина": true, "руслан": true, "савелий": true, "таисия": true, "фархад": true, "хадиджа": true, "элина": true, "эльдар": true}
var enFirstNames = map[string]bool{"james": true, "mary": true, "john": true, "patricia": true, "robert": true, "jennifer": true, "michael": true, "linda": true, "william": true, "elizabeth": true, "david": true, "barbara": true, "richard": true, "susan": true, "joseph": true, "jessica": true, "thomas": true, "sarah": true, "charles": true, "karen": true, "christopher": true, "nancy": true, "daniel": true, "lisa": true, "matthew": true, "betty": true, "anthony": true, "margaret": true, "mark": true, "sandra": true, "donald": true, "ashley": true, "steven": true, "kimberly": true, "paul": true, "emily": true, "andrew": true, "donna": true, "joshua": true, "michelle": true, "kenneth": true, "dorothy": true, "kevin": true, "carol": true, "brian": true, "amanda": true, "george": true, "melissa": true, "edward": true, "deborah": true, "ronald": true, "stephanie": true, "timothy": true, "rebecca": true, "jason": true, "sharon": true, "jeffrey": true, "laura": true, "ryan": true, "cynthia": true, "jacob": true, "kathryn": true, "gary": true, "amy": true, "nicholas": true, "shirley": true, "eric": true, "angela": true, "jonathan": true, "helen": true, "stephen": true, "anna": true, "larry": true, "brenda": true, "justin": true, "pamela": true, "scott": true, "emma": true, "brandon": true, "nicole": true, "benjamin": true, "ruth": true, "samuel": true, "katherine": true, "gregory": true, "olivia": true, "alexander": true, "catherine": true, "frank": true, "martha": true, "raymond": true, "lauren": true, "jack": true, "christina": true}
var ruSurnames = map[string]bool{"иванов": true, "петров": true, "сидоров": true, "смирнов": true, "кузнецов": true, "попов": true, "соколов": true, "михайлов": true, "новиков": true, "федоров": true, "морозов": true, "волков": true, "алексеев": true, "шевченко": true, "козлов": true, "павлов": true, "семенов": true, "голубев": true, "виноградов": true, "богданов": true}
var nameContextWords = []string{"имя", "фамилия", "фио", "клиент", "пациент", "сотрудник", "name", "surname", "customer", "patient", "employee", "user", "client"}

// L6 custom regex supplied from policy (custom_patterns)
type CustomPattern struct {
	Name string
	Re   *regexp.Regexp
}

const maxScanBytes = 1 << 20
const maxJSONDepth = 32

type Session struct {
	mu  sync.Mutex
	Map map[string]string // alias -> real
	Rev map[string]string // real -> alias
	TTL time.Time
	Key []byte
	ctr map[string]int
}

func NewSession(ttl time.Duration) *Session {
	return &Session{Map: map[string]string{}, Rev: map[string]string{}, TTL: time.Now().Add(ttl), ctr: map[string]int{}}
}

func Scan(text string, vaultVals map[string]string, allow map[string]bool) []Finding {
	var out []Finding
	for _, r := range rules() {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			v := text[loc[0]:loc[1]]
			if allow[v] {
				continue
			}
			if r.valid != nil && !r.valid(v) {
				continue
			}
			out = append(out, Finding{Type: r.typ, Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: r.conf, Detector: "regex"})
		}
	}
	// L0 vault match (always on): real vault values in text are SECRET findings.
	// Placeholder-looking values never match as secrets — they pass through.
	for name, val := range vaultVals {
		if val == "" || allow[val] || isPlaceholder(val) {
			continue
		}
		for i := 0; ; {
			j := strings.Index(text[i:], val)
			if j < 0 {
				break
			}
			s := i + j
			out = append(out, Finding{Type: "SECRET:" + name, Span: [2]int{s, s + len(val)}, Value: val, Confidence: 1.0, Detector: "vault"})
			i = s + len(val)
		}
	}
	// L2 entropy: threshold 4.0, window +-120, len>=16; high conf when secret word adjacent
	for _, loc := range mustRe(`\b[A-Za-z0-9_\-+/=]{16,}\b`).FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if allow[v] {
			continue
		}
		e := entropy(v)
		if e > 4.0 && hasSecretWord(text, loc[0]) {
			conf := 0.7
			if e > 4.5 {
				conf = 0.8
			}
			out = append(out, Finding{Type: "HIGH_ENTROPY", Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: conf, Detector: "entropy"})
		}
	}
	// L4 dictionary names with context
	out = append(out, scanNames(text, allow)...)
	// decode one level (base64 / url-encoded / multipart-ish) and scan decoded payloads
	out = append(out, scanDecoded(text, allow)...)
	return dedupe(out)
}

// ScanCustom applies caller-supplied L6 custom regexes from policy (custom_patterns) on top of Scan.
func ScanCustom(text string, vaultVals map[string]string, allow map[string]bool, customs []CustomPattern) []Finding {
	base := Scan(text, vaultVals, allow)
	for _, c := range customs {
		if c.Re == nil {
			continue
		}
		for _, loc := range c.Re.FindAllStringIndex(text, -1) {
			v := text[loc[0]:loc[1]]
			if allow[v] {
				continue
			}
			typ := c.Name
			if typ == "" {
				typ = "CUSTOM"
			}
			base = append(base, Finding{Type: typ, Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: 0.9, Detector: "custom"})
		}
	}
	return dedupe(base)
}

// CompileCustomPatterns compiles raw pattern strings; invalid ones are skipped.
func CompileCustomPatterns(raw map[string]string) []CustomPattern {
	var out []CustomPattern
	for name, pat := range raw {
		re, err := regexp.Compile(pat)
		if err != nil {
			continue
		}
		out = append(out, CustomPattern{Name: name, Re: re})
	}
	return out
}

func scanNames(text string, allow map[string]bool) []Finding {
	var out []Finding
	for _, loc := range mustRe(`[А-ЯЁA-Z][а-яёa-z]+(?:\s+[А-ЯЁA-Z][а-яёa-z]+){1,2}`).FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if allow[v] {
			continue
		}
		parts := strings.Fields(v)
		if len(parts) < 2 {
			continue
		}
		first := strings.ToLower(parts[0])
		known := ruFirstNames[first] || enFirstNames[first]
		if !known && len(parts) > 1 {
			known = ruFirstNames[strings.ToLower(parts[1])] || enFirstNames[strings.ToLower(parts[1])]
		}
		if !known {
			second := strings.ToLower(parts[1])
			if ruSurnames[second] || ruSurnames[first] {
				known = true
			}
		}
		if known && hasNameContext(text, loc[0], loc[1]) {
			out = append(out, Finding{Type: "PERSON_NAME", Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: 0.65, Detector: "dict"})
		}
	}
	return out
}

func hasNameContext(text string, s, e int) bool {
	lo := s - 80
	if lo < 0 {
		lo = 0
	}
	hi := e + 80
	if hi > len(text) {
		hi = len(text)
	}
	win := strings.ToLower(text[lo:hi])
	for _, w := range nameContextWords {
		if strings.Contains(win, strings.ToLower(w)) {
			return true
		}
	}
	return false
}

func scanDecoded(text string, allow map[string]bool) []Finding {
	if len(text) > maxScanBytes {
		text = text[:maxScanBytes]
	}
	var out []Finding
	// base64 blobs: decode one level, scan decoded text for secret-ish tokens
	for _, loc := range mustRe(`\b(?:[A-Za-z0-9+/]{40,}={0,2})`).FindAllStringIndex(text, -1) {
		v := text[loc[0]:loc[1]]
		if len(v)%4 != 0 {
			continue
		}
		dec, err := decodeB64(v)
		if err != nil || len(dec) == 0 || !isMostlyPrintable(dec) {
			continue
		}
		for _, inner := range scanPlain(string(dec)) {
			out = append(out, Finding{Type: inner.Type, Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: inner.Confidence * 0.9, Detector: "decode"})
		}
	}
	// multipart boundary payloads: scan each part body one extra pass via same rules
	if strings.Contains(text, "Content-Disposition:") || strings.Contains(text, "multipart/") {
		for _, inner := range scanPlain(text) {
			out = append(out, Finding{Type: inner.Type, Span: inner.Span, Value: inner.Value, Confidence: inner.Confidence, Detector: "multipart"})
		}
	}
	return out
}

func scanPlain(text string) []Finding {
	var out []Finding
	if len(text) > 64<<10 {
		text = text[:64<<10]
	}
	for _, r := range rules() {
		for _, loc := range r.re.FindAllStringIndex(text, -1) {
			v := text[loc[0]:loc[1]]
			if r.valid != nil && !r.valid(v) {
				continue
			}
			out = append(out, Finding{Type: r.typ, Span: [2]int{loc[0], loc[1]}, Value: v, Confidence: r.conf})
		}
	}
	return out
}

// CheckJSONDepth returns error if nesting exceeds maxJSONDepth or size exceeds cap; never panics.
func CheckJSONDepth(data []byte) error {
	if len(data) > maxScanBytes {
		return fmt.Errorf("payload too large: %d bytes", len(data))
	}
	depth, maxd := 0, 0
	inStr, esc := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{', '[':
			depth++
			if depth > maxd {
				maxd = depth
			}
			if depth > maxJSONDepth {
				return fmt.Errorf("json depth %d exceeds limit %d", depth, maxJSONDepth)
			}
		case '}', ']':
			depth--
			if depth < 0 {
				depth = 0
			}
		}
	}
	return nil
}

// dedupe keeps highest-confidence finding per overlapping span cluster.
func dedupe(in []Finding) []Finding {
	var out []Finding
	used := make([]bool, len(in))
	for i := range in {
		if used[i] {
			continue
		}
		best := i
		for j := range in {
			if used[j] {
				continue
			}
			if overlap(in[best].Span, in[j].Span) && in[j].Confidence > in[best].Confidence {
				best = j
			}
		}
		for j := range in {
			if !used[j] && overlap(in[best].Span, in[j].Span) {
				used[j] = true
			}
		}
		out = append(out, in[best])
	}
	return out
}
func overlap(a, b [2]int) bool { return a[0] < b[1] && b[0] < a[1] }

func entropy(s string) float64 {
	freq := map[rune]float64{}
	for _, r := range s {
		freq[r]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range freq {
		p := c / n
		h -= p * math.Log2(p)
	}
	return h
}

func hasSecretWord(text string, pos int) bool {
	start := pos - 120
	if start < 0 {
		start = 0
	}
	end := pos + 120
	if end > len(text) {
		end = len(text)
	}
	win := strings.ToLower(text[start:end])
	for _, w := range secretWords {
		if strings.Contains(win, w) {
			return true
		}
	}
	return false
}

func decodeB64(v string) ([]byte, error) {
	s := strings.TrimSpace(v)
	if dec, err := base64.StdEncoding.DecodeString(s); err == nil {
		return dec, nil
	}
	return base64.RawStdEncoding.DecodeString(s)
}

func isMostlyPrintable(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	printable := 0
	for _, c := range b {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 32 && c < 127) {
			printable++
		}
	}
	return float64(printable)/float64(len(b)) > 0.8
}

// Apply modes: mask | pseudonymize | hash | block
func Apply(text string, findings []Finding, mode string, sess *Session, threshold float64) (string, error) {
	for _, f := range findings {
		if f.Type == "CREDIT_CARD" || strings.HasPrefix(f.Type, "SECRET") {
			if mode != "allow" {
				// secrets always at least masked
			}
		}
		if f.Confidence < threshold {
			continue
		}
	}
	// replace from end to keep spans valid
	type rep struct {
		s, e int
		with string
	}
	var reps []rep
	for _, f := range findings {
		if f.Confidence < threshold || allowSkip(f) {
			continue
		}
		switch mode {
		case "mask":
			reps = append(reps, rep{f.Span[0], f.Span[1], "[REDACTED:" + shortType(f.Type) + "]"})
		case "pseudonymize":
			reps = append(reps, rep{f.Span[0], f.Span[1], sess.Alias(shortType(f.Type), f.Value)})
		case "hash":
			reps = append(reps, rep{f.Span[0], f.Span[1], shortType(f.Type) + "_" + hmacShort(sess.Key, f.Value)})
		case "block":
			return "", fmt.Errorf("blocked: %s", shortType(f.Type))
		case "block_unless_placeholder":
			if strings.HasPrefix(shortType(f.Type), "SECRET") && isPlaceholder(f.Value) {
				continue
			}
			return "", fmt.Errorf("blocked: %s", shortType(f.Type))
		}
	}
	// sort by start desc
	for i := 0; i < len(reps); i++ {
		for j := i + 1; j < len(reps); j++ {
			if reps[j].s > reps[i].s {
				reps[i], reps[j] = reps[j], reps[i]
			}
		}
	}
	for _, r := range reps {
		text = text[:r.s] + r.with + text[r.e:]
	}
	return text, nil
}

func allowSkip(f Finding) bool {
	// skip low-value IP matches that are actually versions etc. — keep simple
	if f.Type == "IPV4" && f.Confidence < 0.6 {
		return true
	}
	if f.Type == "PHONE" && f.Confidence < 0.7 {
		// require at least 10 digits
		n := 0
		for _, r := range f.Value {
			if unicode.IsDigit(r) {
				n++
			}
		}
		if n < 10 {
			return true
		}
	}
	return false
}

func shortType(t string) string {
	if i := strings.Index(t, ":"); i >= 0 {
		return "SECRET"
	}
	if t == "PHONE_RU" {
		return "PHONE"
	}
	return t
}

func (s *Session) Alias(typ, real string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if a, ok := s.Rev[real]; ok {
		return a
	}
	s.ctr[typ]++
	a := fmt.Sprintf("<%s_%d>", typ, s.ctr[typ])
	s.Rev[real] = a
	s.Map[a] = real
	return a
}

func (s *Session) Rehydrate(text string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for a, real := range s.Map {
		text = strings.ReplaceAll(text, a, real)
	}
	return text
}
func hmacShort(key []byte, v string) string {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:8]
}

// isPlaceholder reports snt://... or SNT_PH_... placeholder values.
func isPlaceholder(v string) bool {
	if strings.HasPrefix(v, "snt://") || strings.HasPrefix(v, "SNT_PH_") {
		return true
	}
	return false
}
