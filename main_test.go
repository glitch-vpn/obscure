package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"text/template"
)

func TestLogProcessor_hashIP(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "IPv4 address",
			ip:       "192.168.1.100",
			expected: "[IPv4:",
		},
		{
			name:     "IPv6 address",
			ip:       "2001:db8::1",
			expected: "[IPv6:",
		},
		{
			name:     "localhost unchanged",
			ip:       "127.0.0.1",
			expected: "127.0.0.1",
		},
		{
			name:     "localhost IPv6 unchanged",
			ip:       "::1",
			expected: "::1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.hashIP(tt.ip)
			if !strings.HasPrefix(result, tt.expected) {
				t.Errorf("hashIP() = %v, want prefix %v", result, tt.expected)
			}

			// Test consistency - same input should give same output
			result2 := processor.hashIP(tt.ip)
			if result != result2 {
				t.Errorf("hashIP() not consistent: %v != %v", result, result2)
			}
		})
	}
}

func TestLogProcessor_processNginxAccessLog(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name        string
		input       string
		contains    []string
		notContains []string
	}{
		{
			name:        "standard nginx access log",
			input:       `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://evil.com" "Mozilla/5.0"`,
			contains:    []string{"[IPv4:", "200", "1234", "[REDACTED]"},
			notContains: []string{"192.168.1.100", "evil.com", "Mozilla"},
		},
		{
			name:        "malformed log returns original",
			input:       "invalid log format",
			contains:    []string{"invalid log format"},
			notContains: []string{"[IPv4:"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processNginxAccessLog(tt.input)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processNginxAccessLog() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processNginxAccessLog() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

func TestLogProcessor_processXrayLog(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name        string
		input       string
		contains    []string
		notContains []string
	}{
		{
			name:        "xray log with UUID and IP",
			input:       `2024/12/25 15:30:45 [Info] VLESS user: 12345678-1234-1234-1234-123456789abc from 192.168.1.100:54321`,
			contains:    []string{"[user_REDACTED]", "[IPv4:", "[PORT_REDACTED]"},
			notContains: []string{"12345678-1234-1234-1234-123456789abc", "192.168.1.100", ":54321"},
		},
		{
			name:        "xray log with timestamp anonymization",
			input:       `2024/12/25 15:30:45 [Warning] Connection failed`,
			contains:    []string{"[ANONYMIZED_TIME]", "[Warning]"},
			notContains: []string{"2024/12/25 15:30:45"},
		},
		{
			name:        "xray log with domains and localhost",
			input:       `2025/06/26 11:48:35.654751 from 127.0.0.1:58002 accepted //www.google.com:443 [http_proxy -> direct]`,
			contains:    []string{"[ANONYMIZED_TIME]", "[IPv4:", "[PORT_REDACTED]", "//[DOMAIN_REDACTED]:443", "[http_proxy -> direct]"},
			notContains: []string{"2025/06/26", "127.0.0.1", ":58002", "www.google.com"},
		},
		{
			name:        "xray log with tcp domain",
			input:       `2025/06/26 11:29:32.171161 from [IPv4:502c95cb312b]:15250 accepted tcp:api2.cursor.sh:443 [vless_reality -> direct] email: [REDACTED]`,
			contains:    []string{"[ANONYMIZED_TIME]", "[IPv4:502c95cb312b]", "[PORT_REDACTED]", "tcp:[DOMAIN_REDACTED]:443", "[vless_reality -> direct]"},
			notContains: []string{"2025/06/26", ":15250", "api2.cursor.sh"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processXrayLog(tt.input)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processXrayLog() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processXrayLog() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

func TestLogProcessor_processWireGuardLog(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name        string
		input       string
		contains    []string
		notContains []string
	}{
		{
			name:        "wireguard peer connection",
			input:       `Dec 25 15:30:45 server kernel: wireguard: wg0: peer ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFG= allowed ips 10.0.0.2/32`,
			contains:    []string{"wg[X]", "[IPv4:", "/32", "[KEY_REDACTED]"},
			notContains: []string{"wg0", "10.0.0.2", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFG="},
		},
		{
			name:        "amneziawg obfuscation parameters",
			input:       `Dec 25 15:30:45 server awg: jc=5 jmin=10 jmax=20 s1=100 s2=200`,
			contains:    []string{"jc=[REDACTED]", "jmin=[REDACTED]", "s1=[REDACTED]"},
			notContains: []string{"jc=5", "jmin=10", "s1=100"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processWireGuardLog(tt.input)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processWireGuardLog() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processWireGuardLog() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

func TestLogProcessor_processManualLog(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name           string
		input          string
		inputTemplate  string
		outputTemplate string
		contains       []string
		notContains    []string
	}{
		{
			name:           "custom web server log",
			input:          "192.168.1.100 john [25/Dec/2024:15:30:45] \"GET /api/user HTTP/1.1\" 200",
			inputTemplate:  `(?P<client_ip>\d+\.\d+\.\d+\.\d+) (?P<user>\w+) (?P<timestamp>\[.*?\]) (?P<request>".*?") (?P<status>\d+)`,
			outputTemplate: "{{salt .client_ip}} {{anonymize .user}} {{.timestamp}} {{.request}} {{.status}}",
			contains:       []string{"f9927a12318f", "[HIDDEN]", "[25/Dec/2024:15:30:45]", "\"GET /api/user HTTP/1.1\"", "200"},
			notContains:    []string{"192.168.1.100", "john"},
		},
		{
			name:           "database log with exotic field names",
			input:          "2024-12-25 user123 SELECT * FROM users WHERE id=42",
			inputTemplate:  `(?P<db_timestamp>\d{4}-\d{2}-\d{2}) (?P<database_user>\w+) (?P<sql_query>.*)`,
			outputTemplate: "{{.db_timestamp}} {{anonymize .database_user}} {{anonymize .sql_query}}",
			contains:       []string{"2024-12-25", "[HIDDEN]"},
			notContains:    []string{"user123", "SELECT * FROM users"},
		},
		{
			name:           "financial transaction log",
			input:          "TX12345 4532-1234-5678-9012 $150.00 Amazon",
			inputTemplate:  `(?P<transaction_id>TX\d+) (?P<credit_card>\d{4}-\d{4}-\d{4}-\d{4}) (?P<amount>\$\d+\.\d{2}) (?P<merchant>\w+)`,
			outputTemplate: "{{.transaction_id}} {{anonymize .credit_card}} {{.amount}} {{anonymize .merchant}}",
			contains:       []string{"TX12345", "[HIDDEN]", "$150.00"},
			notContains:    []string{"4532-1234-5678-9012", "Amazon"},
		},
		{
			name:           "invalid regex should return original",
			input:          "some log line",
			inputTemplate:  `(?P<invalid>[`,
			outputTemplate: "{{.invalid}}",
			contains:       []string{"some log line"},
			notContains:    []string{"[HIDDEN]"},
		},
		{
			name:           "no match should return original",
			input:          "no match here",
			inputTemplate:  `(?P<ip>\d+\.\d+\.\d+\.\d+)`,
			outputTemplate: "{{salt .ip}}",
			contains:       []string{"no match here"},
			notContains:    []string{"f9927a12318f"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processManualLog(tt.input, tt.inputTemplate, tt.outputTemplate)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processManualLog() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processManualLog() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

func TestLogProcessor_processLine(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name     string
		input    string
		logType  string
		contains []string
	}{
		{
			name:     "nginx-access type",
			input:    `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /test HTTP/1.1" 200 1234 "-" "-"`,
			logType:  "nginx-access",
			contains: []string{"[IPv4:"},
		},
		{
			name:     "xray type",
			input:    `2024/12/25 15:30:45 [Info] Connection from 192.168.1.100`,
			logType:  "xray",
			contains: []string{"[IPv4:"},
		},
		{
			name:     "unknown type returns original",
			input:    "unknown log format",
			logType:  "unknown",
			contains: []string{"unknown log format"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processLine(tt.input, tt.logType)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processLine() result should contain %q, got %v", want, result)
				}
			}
		})
	}
}

func TestCreateFIFO(t *testing.T) {
	tempDir := t.TempDir()
	fifoPath := tempDir + "/test.fifo"

	// Test creating new FIFO
	err := createFIFO(fifoPath)
	if err != nil {
		t.Errorf("createFIFO() error = %v", err)
	}

	// Check if FIFO was created
	info, err := os.Stat(fifoPath)
	if err != nil {
		t.Errorf("FIFO not created: %v", err)
	}

	if info.Mode()&os.ModeNamedPipe == 0 {
		t.Errorf("Created file is not a FIFO")
	}

	// Test creating existing FIFO (should not error)
	err = createFIFO(fifoPath)
	if err != nil {
		t.Errorf("createFIFO() on existing FIFO error = %v", err)
	}
}

func TestCreateDefaultConfig(t *testing.T) {
	config := createDefaultConfig()

	if len(config.Pipes) == 0 {
		t.Error("createDefaultConfig() should create pipes")
	}

	// Check that all default pipes have required fields
	for i, pipe := range config.Pipes {
		if pipe.Input == "" {
			t.Errorf("Pipe %d missing Input", i)
		}
		if pipe.Output == "" {
			t.Errorf("Pipe %d missing Output", i)
		}
		if pipe.Type == "" {
			t.Errorf("Pipe %d missing Type", i)
		}

		// Check FIFO extension
		if !strings.HasSuffix(pipe.Input, ".fifo") {
			t.Errorf("Pipe %d Input should end with .fifo, got %s", i, pipe.Input)
		}
	}
}

func TestSaveAndLoadConfig(t *testing.T) {
	tempDir := t.TempDir()
	configPath := tempDir + "/test_config.json"

	// Create test config
	originalConfig := DaemonConfig{
		Pipes: []PipeConfig{
			{
				Input:          "/test/input.fifo",
				Output:         "/test/output.log",
				Type:           "manual",
				InputTemplate:  `(?P<ip>\d+\.\d+\.\d+\.\d+)`,
				OutputTemplate: "{{salt .ip}}",
			},
		},
	}

	// Save config
	err := saveConfig(originalConfig, configPath)
	if err != nil {
		t.Errorf("saveConfig() error = %v", err)
	}

	// Load config
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Errorf("Failed to read config file: %v", err)
	}

	var loadedConfig DaemonConfig
	err = json.Unmarshal(data, &loadedConfig)
	if err != nil {
		t.Errorf("Failed to parse config: %v", err)
	}

	// Compare configs
	if len(loadedConfig.Pipes) != len(originalConfig.Pipes) {
		t.Errorf("Config pipe count mismatch: got %d, want %d", len(loadedConfig.Pipes), len(originalConfig.Pipes))
	}

	pipe := loadedConfig.Pipes[0]
	originalPipe := originalConfig.Pipes[0]

	if pipe.Input != originalPipe.Input {
		t.Errorf("Input mismatch: got %s, want %s", pipe.Input, originalPipe.Input)
	}
	if pipe.Type != originalPipe.Type {
		t.Errorf("Type mismatch: got %s, want %s", pipe.Type, originalPipe.Type)
	}
	if pipe.InputTemplate != originalPipe.InputTemplate {
		t.Errorf("InputTemplate mismatch: got %s, want %s", pipe.InputTemplate, originalPipe.InputTemplate)
	}
	if pipe.OutputTemplate != originalPipe.OutputTemplate {
		t.Errorf("OutputTemplate mismatch: got %s, want %s", pipe.OutputTemplate, originalPipe.OutputTemplate)
	}
}

func TestAnonymizationLevels(t *testing.T) {
	tests := []struct {
		name           string
		level          string
		input          string
		checkTimestamp bool
	}{
		{
			name:           "low level keeps timestamps",
			level:          "low",
			input:          `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /test HTTP/1.1" 200 1234 "-" "-"`,
			checkTimestamp: true,
		},
		{
			name:           "high level anonymizes timestamps",
			level:          "high",
			input:          `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /test HTTP/1.1" 200 1234 "-" "-"`,
			checkTimestamp: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			processor := NewLogProcessor("test-salt", tt.level)
			result := processor.processNginxAccessLog(tt.input)

			if tt.checkTimestamp {
				if !strings.Contains(result, "25/Dec/2024:15:30:45") {
					t.Errorf("Low level should preserve timestamps, got %v", result)
				}
			} else {
				if strings.Contains(result, "25/Dec/2024:15:30:45") {
					t.Errorf("High level should anonymize timestamps, got %v", result)
				}
			}
		})
	}
}

// Benchmark tests
func BenchmarkLogProcessor_hashIP(b *testing.B) {
	processor := NewLogProcessor("benchmark-salt", "high")
	ip := "192.168.1.100"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.hashIP(ip)
	}
}

func BenchmarkLogProcessor_processNginxAccessLog(b *testing.B) {
	processor := NewLogProcessor("benchmark-salt", "high")
	logLine := `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0"`

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.processNginxAccessLog(logLine)
	}
}

func BenchmarkLogProcessor_processManualLog(b *testing.B) {
	processor := NewLogProcessor("benchmark-salt", "high")
	logLine := "192.168.1.100 john [25/Dec/2024:15:30:45] \"GET /api/user HTTP/1.1\" 200"
	inputTemplate := `(?P<ip>\d+\.\d+\.\d+\.\d+) (?P<user>\w+) (?P<timestamp>\[.*?\]) (?P<request>".*?") (?P<status>\d+)`
	outputTemplate := "{{salt .ip}} {{anonymize .user}} {{.timestamp}} {{.request}} {{.status}}"

	// Pre-compile regex and template to make benchmark realistic
	regex := regexp.MustCompile(inputTemplate)
	tmpl := template.Must(template.New("output").Funcs(template.FuncMap{
		"salt": func(value string) string {
			return processor.hashIP(value)
		},
		"anonymize": func(value string) string {
			return "[HIDDEN]"
		},
	}).Parse(outputTemplate))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		matches := regex.FindStringSubmatch(logLine)
		if matches != nil {
			groupNames := regex.SubexpNames()
			groups := make(map[string]string)
			for j, name := range groupNames {
				if j > 0 && name != "" && j < len(matches) {
					groups[name] = matches[j]
				}
			}
			var buf bytes.Buffer
			tmpl.Execute(&buf, groups)
		}
	}
}

// Integration tests
func TestLogProcessor_processLine_integration(t *testing.T) {
	processor := NewLogProcessor("integration-salt", "high")

	tests := []struct {
		name        string
		input       string
		logType     string
		contains    []string
		notContains []string
	}{
		{
			name:        "nginx access with manual template",
			input:       `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /api/users HTTP/1.1" 200 1234 "https://evil.com" "Mozilla/5.0"`,
			logType:     "nginx-access",
			contains:    []string{"[IPv4:", "[REDACTED]"},
			notContains: []string{"192.168.1.100", "evil.com", "Mozilla"},
		},
		{
			name:        "xray with multiple sensitive data",
			input:       `2024/12/25 15:30:45 [Info] VLESS user: john@evil.com privateKey: ABC123XYZ from 192.168.1.100:54321`,
			logType:     "xray",
			contains:    []string{"[user_REDACTED]", "[privateKey_REDACTED]", "[IPv4:"},
			notContains: []string{"john@evil.com", "ABC123XYZ", "192.168.1.100"},
		},
		{
			name:        "wireguard with amneziawg params",
			input:       `Dec 25 15:30:45 server awg: wg0 jc=5 jmin=10 s1=100 peer ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFG= from 10.0.0.2`,
			logType:     "wireguard",
			contains:    []string{"wg[X]", "jc=[REDACTED]", "[KEY_REDACTED]", "[IPv4:"},
			notContains: []string{"wg0", "jc=5", "ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890ABCDEFG=", "10.0.0.2"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processLine(tt.input, tt.logType)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processLine() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processLine() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

// Edge case tests
func TestLogProcessor_edgeCases(t *testing.T) {
	processor := NewLogProcessor("edge-salt", "high")

	tests := []struct {
		name     string
		input    string
		logType  string
		expected string
	}{
		{
			name:     "empty line",
			input:    "",
			logType:  "nginx-access",
			expected: "",
		},
		{
			name:     "malformed nginx log",
			input:    "not a valid nginx log format",
			logType:  "nginx-access",
			expected: "not a valid nginx log format",
		},
		{
			name:     "line with only spaces",
			input:    "   ",
			logType:  "xray",
			expected: "   ",
		},
		{
			name:     "very long line",
			input:    strings.Repeat("x", 1000) + " 192.168.1.100 " + strings.Repeat("y", 1000),
			logType:  "xray",
			expected: "", // Just check it doesn't crash
		},
		{
			name:     "unicode characters",
			input:    "2024/12/25 15:30:45 [Info] Connection from 192.168.1.100 with 中文字符 and émojis 🚀",
			logType:  "xray",
			expected: "", // Just check it doesn't crash
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processLine(tt.input, tt.logType)

			// For empty expected, just check it doesn't crash
			if tt.expected == "" && tt.name != "empty line" && tt.name != "line with only spaces" {
				if result == "" {
					t.Errorf("processLine() returned empty result for %q", tt.input)
				}
				return
			}

			if tt.expected != "" && result != tt.expected {
				t.Errorf("processLine() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// Performance stress test
func TestLogProcessor_concurrency(t *testing.T) {
	processor := NewLogProcessor("concurrency-salt", "high")

	// Test concurrent access to IP hash cache
	const numGoroutines = 50
	const numOperations = 100

	done := make(chan bool, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			for j := 0; j < numOperations; j++ {
				ip := fmt.Sprintf("192.168.%d.%d", id%255, j%255)
				hash1 := processor.hashIP(ip)
				hash2 := processor.hashIP(ip)

				if hash1 != hash2 {
					t.Errorf("Inconsistent hash for IP %s: %s != %s", ip, hash1, hash2)
				}
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		<-done
	}
}

// Test anonymization level differences
func TestLogProcessor_anonymizationLevelDifferences(t *testing.T) {
	testLine := `192.168.1.100 [25/Dec/2024:15:30:45 +0000] "GET /test HTTP/1.1" 200 1234 "https://ref.com" "Mozilla"`

	lowProcessor := NewLogProcessor("test-salt", "low")
	highProcessor := NewLogProcessor("test-salt", "high")

	lowResult := lowProcessor.processNginxAccessLog(testLine)
	highResult := highProcessor.processNginxAccessLog(testLine)

	// Low level should preserve timestamp
	if !strings.Contains(lowResult, "25/Dec/2024:15:30:45") {
		t.Errorf("Low level should preserve timestamp, got %v", lowResult)
	}

	// High level should anonymize timestamp
	if strings.Contains(highResult, "25/Dec/2024:15:30:45") {
		t.Errorf("High level should anonymize timestamp, got %v", highResult)
	}

	// Both should anonymize IPs the same way
	lowIP := regexp.MustCompile(`\[IPv4:[a-f0-9]{12}\]`).FindString(lowResult)
	highIP := regexp.MustCompile(`\[IPv4:[a-f0-9]{12}\]`).FindString(highResult)

	if lowIP != highIP {
		t.Errorf("IP hashing should be consistent across levels: %s != %s", lowIP, highIP)
	}
}

func TestLogProcessor_processJSONLog(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name            string
		input           string
		anonymizeFields []string
		saltFields      []string
		contains        []string
		notContains     []string
	}{
		{
			name:            "simple JSON with username anonymization",
			input:           `{"username": "alice", "action": "login", "ip": "192.168.1.100"}`,
			anonymizeFields: []string{"username"},
			saltFields:      []string{"ip"},
			contains:        []string{`"username":"[REDACTED]"`, `"action":"login"`, `[IPv4:`},
			notContains:     []string{"alice", "192.168.1.100"},
		},
		{
			name:            "nested JSON with secure fields",
			input:           `{"user": {"name": "bob", "key": "secret123"}, "metadata": {"ip_address": "10.0.0.1"}}`,
			anonymizeFields: []string{"name"},
			saltFields:      []string{"key", "ip"},
			contains:        []string{`"name":"[REDACTED]"`, `[IPv4:`},
			notContains:     []string{"bob", "secret123", "10.0.0.1"},
		},
		{
			name:            "invalid JSON returns original",
			input:           `{invalid json}`,
			anonymizeFields: []string{"username"},
			saltFields:      []string{"ip"},
			contains:        []string{"{invalid json}"},
			notContains:     []string{},
		},
		{
			name:            "JSON array with nested objects",
			input:           `{"users": [{"username": "alice", "pass": "secret"}, {"username": "bob", "pass": "hidden"}]}`,
			anonymizeFields: []string{"username"},
			saltFields:      []string{"pass"},
			contains:        []string{`"username":"[REDACTED]"`},
			notContains:     []string{"alice", "bob", "secret", "hidden"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.processJSONLog(tt.input, tt.anonymizeFields, tt.saltFields)

			for _, want := range tt.contains {
				if !strings.Contains(result, want) {
					t.Errorf("processJSONLog() result should contain %q, got %v", want, result)
				}
			}

			for _, notWant := range tt.notContains {
				if strings.Contains(result, notWant) {
					t.Errorf("processJSONLog() result should not contain %q, got %v", notWant, result)
				}
			}
		})
	}
}

func TestLogProcessor_processJSONKeys(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name            string
		data            map[string]interface{}
		anonymizeFields []string
		saltFields      []string
		expectAnonymize []string
		expectSalt      []string
	}{
		{
			name: "case insensitive matching",
			data: map[string]interface{}{
				"USERNAME":  "alice",
				"UserEmail": "alice@test.com",
				"client_ip": "192.168.1.1",
			},
			anonymizeFields: []string{"user"},
			saltFields:      []string{"ip"},
			expectAnonymize: []string{"USERNAME", "UserEmail"},
			expectSalt:      []string{"client_ip"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			originalData := make(map[string]interface{})
			for k, v := range tt.data {
				originalData[k] = v
			}

			processor.processJSONKeys(tt.data, tt.anonymizeFields, tt.saltFields)

			// Check anonymized fields
			for _, field := range tt.expectAnonymize {
				if value, ok := tt.data[field]; ok {
					if value != "[REDACTED]" {
						t.Errorf("Field %s should be anonymized to [REDACTED], got %v", field, value)
					}
				}
			}

			// Check salted fields
			for _, field := range tt.expectSalt {
				if value, ok := tt.data[field]; ok {
					originalValue := originalData[field].(string)
					if value == originalValue {
						t.Errorf("Field %s should be salted/hashed, but remained unchanged: %v", field, value)
					}
				}
			}
		})
	}
}

func TestLogProcessor_hashValue(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name  string
		input string
	}{
		{"simple string", "hello"},
		{"complex string", "complex_password_123"},
		{"empty string", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.hashValue(tt.input)

			// Check that result is a 12-character hex string
			if len(result) != 12 {
				t.Errorf("hashValue() should return 12 character string, got %d: %s", len(result), result)
			}

			// Check that it's consistent
			result2 := processor.hashValue(tt.input)
			if result != result2 {
				t.Errorf("hashValue() not consistent: %v != %v", result, result2)
			}

			// Check that different inputs give different outputs (unless empty)
			if tt.input != "" {
				differentResult := processor.hashValue(tt.input + "_different")
				if result == differentResult {
					t.Errorf("hashValue() should give different results for different inputs")
				}
			}
		})
	}
}

func TestPipeConfig_JSONFormat(t *testing.T) {
	// Test config parsing with new fields
	configJSON := `{
		"pipes": [
			{
				"input": "/test/input.fifo",
				"output": "/test/output.log", 
				"type": "manual",
				"format": "json",
				"anonymize_fields": ["user", "email"],
				"salt_fields": ["ip", "key"]
			}
		]
	}`

	var config DaemonConfig
	err := json.Unmarshal([]byte(configJSON), &config)
	if err != nil {
		t.Fatalf("Failed to parse config: %v", err)
	}

	pipe := config.Pipes[0]
	if pipe.Format != "json" {
		t.Errorf("Expected format 'json', got '%s'", pipe.Format)
	}

	expectedAnonymize := []string{"user", "email"}
	if !reflect.DeepEqual(pipe.AnonymizeFields, expectedAnonymize) {
		t.Errorf("Expected anonymize_fields %v, got %v", expectedAnonymize, pipe.AnonymizeFields)
	}

	expectedSalt := []string{"ip", "key"}
	if !reflect.DeepEqual(pipe.SaltFields, expectedSalt) {
		t.Errorf("Expected salt_fields %v, got %v", expectedSalt, pipe.SaltFields)
	}
}

func BenchmarkLogProcessor_processJSONLog(b *testing.B) {
	processor := NewLogProcessor("test-salt", "high")
	jsonLine := `{"username": "alice", "action": "login", "ip": "192.168.1.100", "timestamp": "2024-01-01T12:00:00Z", "user_agent": "Mozilla/5.0"}`
	anonymizeFields := []string{"username", "user"}
	saltFields := []string{"ip"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processor.processJSONLog(jsonLine, anonymizeFields, saltFields)
	}
}

func TestLogProcessor_forceHashIP(t *testing.T) {
	processor := NewLogProcessor("test-salt", "high")

	tests := []struct {
		name     string
		ip       string
		expected string
	}{
		{
			name:     "IPv4 address",
			ip:       "192.168.1.100",
			expected: "[IPv4:",
		},
		{
			name:     "IPv6 address",
			ip:       "2001:db8::1",
			expected: "[IPv6:",
		},
		{
			name:     "localhost IPv4 gets hashed",
			ip:       "127.0.0.1",
			expected: "[IPv4:",
		},
		{
			name:     "localhost IPv6 gets hashed",
			ip:       "::1",
			expected: "[IPv6:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := processor.forceHashIP(tt.ip)
			if !strings.HasPrefix(result, tt.expected) {
				t.Errorf("forceHashIP() = %v, want prefix %v", result, tt.expected)
			}

			// Test consistency - same input should give same output
			result2 := processor.forceHashIP(tt.ip)
			if result != result2 {
				t.Errorf("forceHashIP() not consistent: %v != %v", result, result2)
			}

			// Verify localhost IPs are NOT preserved (different from hashIP)
			if tt.ip == "127.0.0.1" || tt.ip == "::1" {
				if result == tt.ip {
					t.Errorf("forceHashIP() should hash localhost %v, but got %v", tt.ip, result)
				}
			}
		})
	}
}
