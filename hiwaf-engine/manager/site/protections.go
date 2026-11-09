package site

// Protection is one WAF checkbox and the CRS rule-ID ranges it covers.
type Protection struct {
	Key      string   `json:"key"`
	Label    string   `json:"label"`
	IDRanges []string `json:"id_ranges"`
	Default  bool     `json:"default"`
}

// Protections is the checkbox catalog, in display order.
var Protections = []Protection{
	{Key: "sqli", Label: "SQL injection", IDRanges: []string{"942000-942999"}, Default: true},
	{Key: "xss", Label: "Cross-site scripting", IDRanges: []string{"941000-941999"}, Default: true},
	{Key: "rce", Label: "Command injection", IDRanges: []string{"932000-932999"}, Default: true},
	{Key: "lfi", Label: "Path traversal / local file", IDRanges: []string{"930000-930999"}, Default: true},
	{Key: "rfi", Label: "Remote file inclusion", IDRanges: []string{"931000-931999"}, Default: true},
	{Key: "php", Label: "PHP injection", IDRanges: []string{"933000-933999"}, Default: true},
	{Key: "nodejs", Label: "Node.js injection", IDRanges: []string{"934000-934999"}, Default: true},
	{Key: "java", Label: "Java / deserialization", IDRanges: []string{"944000-944999"}, Default: true},
	{Key: "session_fixation", Label: "Session fixation", IDRanges: []string{"943000-943999"}, Default: true},
	{Key: "scanner", Label: "Scanner / bad-bot detection", IDRanges: []string{"913000-913999"}, Default: true},
	{Key: "protocol", Label: "Protocol attacks + enforcement", IDRanges: []string{"920000-920999", "921000-921999", "922000-922999"}, Default: true},
	{Key: "data_leak", Label: "Response data leakage (needs response body inspection)", IDRanges: []string{"950000-956999"}, Default: false},
}
