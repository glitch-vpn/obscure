package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"text/template"
	"time"
)

type LogProcessor struct {
	salt           []byte
	anonymizeLevel string

	// Pre-compiled regex patterns for performance
	ipv4Pattern        *regexp.Regexp
	ipv6Pattern        *regexp.Regexp
	timestampPatterns  map[string]*regexp.Regexp
	nginxAccessPattern *regexp.Regexp
	nginxStreamPattern *regexp.Regexp

	// Xray specific patterns
	uuidPattern        *regexp.Regexp
	realityKeyPattern  *regexp.Regexp
	shadowsocksPattern *regexp.Regexp

	// WireGuard patterns
	peerKeyPattern        *regexp.Regexp
	awgObfuscationPattern *regexp.Regexp

	// Cache for IP hashes to avoid recomputation
	ipHashCache map[string]string
	cacheMutex  sync.RWMutex
}

func NewLogProcessor(salt string, level string) *LogProcessor {
	processor := &LogProcessor{
		salt:           []byte(salt),
		anonymizeLevel: level,
		ipHashCache:    make(map[string]string),
	}

	// Pre-compile all regex patterns
	processor.ipv4Pattern = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	processor.ipv6Pattern = regexp.MustCompile(`(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`)

	processor.timestampPatterns = map[string]*regexp.Regexp{
		"nginx":   regexp.MustCompile(`\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}`),
		"xray":    regexp.MustCompile(`\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}`),
		"systemd": regexp.MustCompile(`\w{3} \d{1,2} \d{2}:\d{2}:\d{2}`),
	}

	processor.nginxAccessPattern = regexp.MustCompile(`^(\S+) \[([^\]]+)\] "([^"]*)" (\d+) (\d+) "([^"]*)" "([^"]*)"`)
	processor.nginxStreamPattern = regexp.MustCompile(`^(\S+) \[([^\]]+)\] (\S+) (\d+) (\d+) (\d+) ([\d.]+) "([^"]*)" "([^"]*)"`)

	// Xray patterns
	processor.uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
	processor.realityKeyPattern = regexp.MustCompile(`(privateKey|publicKey|shortId|fingerprint)[\s":]*([A-Za-z0-9+/=:]{8,})`)
	processor.shadowsocksPattern = regexp.MustCompile(`(password|method|path|serverName|dest|user|pass)[\s":]*([^\s",}]+)`)

	// WireGuard patterns
	processor.peerKeyPattern = regexp.MustCompile(`peer [A-Za-z0-9+/]{43}=`)
	processor.awgObfuscationPattern = regexp.MustCompile(`(jc|jmin|jmax|s[12]|h[1-4])=\d+`)

	return processor
}

func (p *LogProcessor) hashIP(ip string) string {
	// Skip localhost and invalid IPs
	if ip == "127.0.0.1" || ip == "::1" || ip == "localhost" {
		return ip
	}

	// Check cache first
	p.cacheMutex.RLock()
	if cached, exists := p.ipHashCache[ip]; exists {
		p.cacheMutex.RUnlock()
		return cached
	}
	p.cacheMutex.RUnlock()

	// Generate hash
	hasher := sha256.New()
	hasher.Write([]byte(ip))
	hasher.Write(p.salt)
	hashBytes := hasher.Sum(nil)
	shortHash := hex.EncodeToString(hashBytes)[:12]

	// Determine IP type and format result with type info
	var result string
	if strings.Contains(ip, ":") {
		// IPv6 address
		result = fmt.Sprintf("[IPv6:%s]", shortHash)
	} else {
		// IPv4 address
		result = fmt.Sprintf("[IPv4:%s]", shortHash)
	}

	// Cache the result
	p.cacheMutex.Lock()
	p.ipHashCache[ip] = result
	p.cacheMutex.Unlock()

	return result
}

func (p *LogProcessor) anonymizeTimestamp(timestamp, format string) string {
	if p.anonymizeLevel == "low" {
		return timestamp
	}
	return "[ANONYMIZED_TIME]"
}

func (p *LogProcessor) processNginxAccessLog(line string) string {
	matches := p.nginxAccessPattern.FindStringSubmatch(line)
	if len(matches) != 8 {
		return line
	}

	ip := p.hashIP(matches[1])
	timestamp := p.anonymizeTimestamp(matches[2], "nginx")
	request := regexp.MustCompile(`(\?|&)[^=]*=[^&\s]*`).ReplaceAllString(matches[3], `$1[PARAM]=[REDACTED]`)
	referer := "[REDACTED]"
	if matches[6] == "-" {
		referer = "-"
	}
	userAgent := "[REDACTED]"
	if matches[7] == "-" {
		userAgent = "-"
	}

	return fmt.Sprintf(`%s [%s] "%s" %s %s "%s" "%s"`,
		ip, timestamp, request, matches[4], matches[5], referer, userAgent)
}

func (p *LogProcessor) processNginxStreamLog(line string) string {
	matches := p.nginxStreamPattern.FindStringSubmatch(line)
	if len(matches) != 10 {
		return line
	}

	ip := p.hashIP(matches[1])
	timestamp := p.anonymizeTimestamp(matches[2], "nginx")
	sni := "[SNI_REDACTED]"
	if matches[9] == "" {
		sni = `""`
	}

	return fmt.Sprintf(`%s [%s] %s %s %s %s %s "%s" %s`,
		ip, timestamp, matches[3], matches[4], matches[5], matches[6], matches[7], matches[8], sni)
}

func (p *LogProcessor) processXrayLog(line string) string {
	// Anonymize timestamps
	if p.anonymizeLevel != "low" {
		line = p.timestampPatterns["xray"].ReplaceAllString(line, "[ANONYMIZED_TIME]")
	}

	// Anonymize IPs
	line = p.ipv4Pattern.ReplaceAllStringFunc(line, p.hashIP)
	line = p.ipv6Pattern.ReplaceAllStringFunc(line, p.hashIP)

	// Anonymize UUIDs
	line = p.uuidPattern.ReplaceAllString(line, "[UUID_REDACTED]")

	// Anonymize REALITY and other sensitive data
	line = p.realityKeyPattern.ReplaceAllString(line, "$1: [${1}_REDACTED]")
	line = p.shadowsocksPattern.ReplaceAllString(line, "$1: [${1}_REDACTED]")

	// Anonymize user emails
	emailPattern := regexp.MustCompile(`(user|email):\s*\S+@\S+`)
	line = emailPattern.ReplaceAllString(line, "$1: [REDACTED]")

	return line
}

func (p *LogProcessor) processWireGuardLog(line string) string {
	// Anonymize timestamps
	if p.anonymizeLevel != "low" {
		line = p.timestampPatterns["systemd"].ReplaceAllString(line, "[ANONYMIZED_TIME]")
	}

	// Anonymize IPs
	line = p.ipv4Pattern.ReplaceAllStringFunc(line, p.hashIP)
	line = p.ipv6Pattern.ReplaceAllStringFunc(line, p.hashIP)

	// Anonymize peer keys
	line = p.peerKeyPattern.ReplaceAllString(line, "peer [KEY_REDACTED]")

	// Anonymize AmneziaWG obfuscation parameters
	line = p.awgObfuscationPattern.ReplaceAllString(line, "$1=[REDACTED]")

	// Anonymize interface names
	interfacePattern := regexp.MustCompile(`(wg|awg)\d+`)
	line = interfacePattern.ReplaceAllString(line, "${1}[X]")

	return line
}

func (p *LogProcessor) processOpenVPNLog(line string) string {
	// Anonymize timestamps
	if p.anonymizeLevel != "low" {
		line = p.timestampPatterns["systemd"].ReplaceAllString(line, "[ANONYMIZED_TIME]")
	}

	// Anonymize IPs
	line = p.ipv4Pattern.ReplaceAllStringFunc(line, p.hashIP)

	// Anonymize certificate names
	cnPattern := regexp.MustCompile(`CN=([^,\s]+)`)
	line = cnPattern.ReplaceAllString(line, "CN=[CERT_REDACTED]")

	return line
}

func (p *LogProcessor) processManualLog(line, inputTemplate, outputTemplate string) string {
	// Compile regex
	regex, err := regexp.Compile(inputTemplate)
	if err != nil {
		log.Printf("Invalid regex pattern: %v", err)
		return line
	}

	// Find matches
	matches := regex.FindStringSubmatch(line)
	if matches == nil {
		return line // No match, return original
	}

	// Get named groups
	groupNames := regex.SubexpNames()
	groups := make(map[string]string)

	for i, name := range groupNames {
		if i > 0 && name != "" && i < len(matches) {
			groups[name] = matches[i]
		}
	}

	// Create template functions
	funcMap := template.FuncMap{
		"salt": func(value string) string {
			// Just return raw hash without any prefixes
			hasher := sha256.New()
			hasher.Write([]byte(value))
			hasher.Write(p.salt)
			hashBytes := hasher.Sum(nil)
			return hex.EncodeToString(hashBytes)[:12]
		},
		"anonymize": func(value string) string {
			return "[HIDDEN]"
		},
	}

	// Parse template with functions
	tmpl, err := template.New("output").Funcs(funcMap).Parse(outputTemplate)
	if err != nil {
		log.Printf("Invalid output template: %v", err)
		return line
	}

	// Execute template
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, groups); err != nil {
		log.Printf("Template execution error: %v", err)
		return line
	}

	return buf.String()
}

func (p *LogProcessor) processLine(line, logType string) string {
	switch logType {
	case "nginx-access":
		return p.processNginxAccessLog(line)
	case "nginx-stream":
		return p.processNginxStreamLog(line)
	case "xray":
		return p.processXrayLog(line)
	case "wireguard", "amneziawg":
		return p.processWireGuardLog(line)
	case "openvpn":
		return p.processOpenVPNLog(line)
	default:
		return line
	}
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	command := os.Args[1]

	switch command {
	case "setup":
		runSetupCommand()
	case "start":
		runStartCommand()
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", command)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Obscure - Real-time VPN Log Anonymizer\n\n")
	fmt.Fprintf(os.Stderr, "Usage: obscure [COMMAND] [OPTIONS]\n\n")
	fmt.Fprintf(os.Stderr, "Commands:\n")
	fmt.Fprintf(os.Stderr, "  setup                    Setup FIFOs and config, then exit\n")
	fmt.Fprintf(os.Stderr, "    Options:\n")
	fmt.Fprintf(os.Stderr, "      --config, -c [path]    Path to config file (default: /etc/obscure/pipes.conf)\n")
	fmt.Fprintf(os.Stderr, "      --salt, -s [string]    Salt for hashing\n\n")
	fmt.Fprintf(os.Stderr, "  start                    Start log processing daemon\n")
	fmt.Fprintf(os.Stderr, "    Options:\n")
	fmt.Fprintf(os.Stderr, "      --config, -c [path]    Path to config file (default: /etc/obscure/pipes.conf)\n")
	fmt.Fprintf(os.Stderr, "      --salt, -s [string]    Salt for hashing\n")
	fmt.Fprintf(os.Stderr, "      --daemon, -d           Start process as daemon (default: true)\n")
	fmt.Fprintf(os.Stderr, "      --level, -l [level]    Anonymization level: low, medium, high (default: high)\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  sudo obscure setup\n")
	fmt.Fprintf(os.Stderr, "  sudo obscure setup --config /custom/path.conf --salt mysecret\n")
	fmt.Fprintf(os.Stderr, "  sudo obscure start\n")
	fmt.Fprintf(os.Stderr, "  sudo obscure start --config /custom/path.conf --level medium\n")
}

func runSetupCommand() {
	setupFlags := flag.NewFlagSet("setup", flag.ExitOnError)
	configFile := setupFlags.String("config", "/etc/obscure/pipes.conf", "Path to config file")
	configFileShort := setupFlags.String("c", "/etc/obscure/pipes.conf", "Path to config file (short)")
	salt := setupFlags.String("salt", "", "Salt for hashing")
	saltShort := setupFlags.String("s", "", "Salt for hashing (short)")

	setupFlags.Parse(os.Args[2:])

	// Use short flag value if long flag is default
	if *configFile == "/etc/obscure/pipes.conf" && *configFileShort != "/etc/obscure/pipes.conf" {
		*configFile = *configFileShort
	}
	if *salt == "" && *saltShort != "" {
		*salt = *saltShort
	}

	runSetup(*configFile, *salt)
}

func runStartCommand() {
	startFlags := flag.NewFlagSet("start", flag.ExitOnError)
	configFile := startFlags.String("config", "/etc/obscure/pipes.conf", "Path to config file")
	configFileShort := startFlags.String("c", "/etc/obscure/pipes.conf", "Path to config file (short)")
	salt := startFlags.String("salt", "", "Salt for hashing")
	saltShort := startFlags.String("s", "", "Salt for hashing (short)")
	daemon := startFlags.Bool("daemon", true, "Start process as daemon")
	daemonShort := startFlags.Bool("d", true, "Start process as daemon (short)")
	level := startFlags.String("level", "high", "Anonymization level (low, medium, high)")
	levelShort := startFlags.String("l", "high", "Anonymization level (short)")

	startFlags.Parse(os.Args[2:])

	// Use short flag values if long flags are default
	if *configFile == "/etc/obscure/pipes.conf" && *configFileShort != "/etc/obscure/pipes.conf" {
		*configFile = *configFileShort
	}
	if *salt == "" && *saltShort != "" {
		*salt = *saltShort
	}
	if *daemon == true && *daemonShort != true {
		*daemon = *daemonShort
	}
	if *level == "high" && *levelShort != "high" {
		*level = *levelShort
	}

	if *daemon {
		runDaemon(*configFile, *salt, *level)
	} else {
		fmt.Fprintf(os.Stderr, "Non-daemon mode not implemented. Use --daemon flag.\n")
		os.Exit(1)
	}
}

type PipeConfig struct {
	Input          string `json:"input"`           // FIFO path
	Output         string `json:"output"`          // Output file
	Type           string `json:"type"`            // Log type or "manual"
	InputTemplate  string `json:"input_template"`  // Regex pattern for manual type
	OutputTemplate string `json:"output_template"` // Output template for manual type
}

type DaemonConfig struct {
	Pipes []PipeConfig `json:"pipes"`
}

// Daemon mode - reads from FIFO pipes continuously
func runDaemon(configPath, salt, level string) {
	log.Printf("Starting obscure daemon mode...")

	var config DaemonConfig

	// If config file exists, read it
	if configData, err := os.ReadFile(configPath); err == nil {
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Fatalf("Failed to parse config: %v", err)
		}
	} else {
		// Create default config
		log.Printf("Config not found, creating default: %s", configPath)
		config = createDefaultConfig()
		saveConfig(config, configPath)
	}

	// Create all FIFOs
	for _, pipe := range config.Pipes {
		if err := createFIFO(pipe.Input); err != nil {
			log.Printf("Warning: Failed to create FIFO %s: %v", pipe.Input, err)
		} else {
			log.Printf("FIFO ready: %s", pipe.Input)
		}
	}

	// Start workers for each pipe
	var wg sync.WaitGroup
	for _, pipe := range config.Pipes {
		wg.Add(1)
		go func(p PipeConfig) {
			defer wg.Done()
			processPipe(p, salt, level)
		}(pipe)
	}

	log.Printf("Started %d pipe workers", len(config.Pipes))
	wg.Wait()
}

// Process single FIFO pipe
func processPipe(pipe PipeConfig, salt, level string) {
	processor := NewLogProcessor(salt, level)

	for {
		// Open FIFO for reading (blocks until writer appears)
		log.Printf("Opening FIFO: %s", pipe.Input)
		fifo, err := os.OpenFile(pipe.Input, os.O_RDONLY, 0)
		if err != nil {
			log.Printf("Failed to open FIFO %s: %v", pipe.Input, err)
			time.Sleep(5 * time.Second)
			continue
		}

		// Open output file
		outputDir := filepath.Dir(pipe.Output)
		os.MkdirAll(outputDir, 0755)

		output, err := os.OpenFile(pipe.Output, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			log.Printf("Failed to open output %s: %v", pipe.Output, err)
			fifo.Close()
			time.Sleep(5 * time.Second)
			continue
		}

		// Process lines from FIFO
		scanner := bufio.NewScanner(fifo)
		writer := bufio.NewWriter(output)

		for scanner.Scan() {
			line := scanner.Text()
			var processed string

			if pipe.Type == "manual" {
				processed = processor.processManualLog(line, pipe.InputTemplate, pipe.OutputTemplate)
			} else {
				processed = processor.processLine(line, pipe.Type)
			}

			writer.WriteString(processed + "\n")
			writer.Flush()
		}

		// Clean up when FIFO closes
		fifo.Close()
		output.Close()

		if err := scanner.Err(); err != nil {
			log.Printf("Scanner error on %s: %v", pipe.Input, err)
		}

		log.Printf("FIFO %s closed, reopening...", pipe.Input)
	}
}

// Create FIFO if it doesn't exist
func createFIFO(path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		dir := filepath.Dir(path)
		os.MkdirAll(dir, 0755)
		return syscall.Mkfifo(path, 0644)
	}
	return nil
}

// Create default configuration
func createDefaultConfig() DaemonConfig {
	return DaemonConfig{
		Pipes: []PipeConfig{
			{
				Input:  "/var/log/nginx/access.fifo",
				Output: "/var/log/vpn-anonymized/nginx_access.log",
				Type:   "nginx-access",
			},
			{
				Input:  "/var/log/nginx/stream.fifo",
				Output: "/var/log/vpn-anonymized/nginx_stream.log",
				Type:   "nginx-stream",
			},
			{
				Input:  "/var/log/xray/access.fifo",
				Output: "/var/log/vpn-anonymized/xray_access.log",
				Type:   "xray",
			},
			{
				Input:  "/var/log/openvpn/access.fifo",
				Output: "/var/log/vpn-anonymized/openvpn_access.log",
				Type:   "openvpn",
			},
		},
	}
}

// Save configuration to file
func saveConfig(config DaemonConfig, path string) error {
	dir := filepath.Dir(path)
	os.MkdirAll(dir, 0755)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

// Setup mode - create FIFOs and config, then exit
func runSetup(configPath, salt string) {
	log.Printf("Setting up obscure daemon...")

	var config DaemonConfig
	var configExists bool

	// Check if config already exists
	if configData, err := os.ReadFile(configPath); err == nil {
		configExists = true
		if err := json.Unmarshal(configData, &config); err != nil {
			log.Fatalf("Failed to parse existing config: %v", err)
		}
		log.Printf("Found existing config with %d pipes", len(config.Pipes))
	} else {
		// Create default config for new installations
		config = createDefaultConfig()
		log.Printf("Creating new config with %d default pipes", len(config.Pipes))
	}

	// Create all FIFOs from config
	for _, pipe := range config.Pipes {
		if err := createFIFO(pipe.Input); err != nil {
			log.Printf("Failed to create FIFO %s: %v", pipe.Input, err)
		} else {
			log.Printf("FIFO ready: %s", pipe.Input)
		}

		// Create output directory
		outputDir := filepath.Dir(pipe.Output)
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			log.Printf("Failed to create output dir %s: %v", outputDir, err)
		} else {
			log.Printf("Output directory ready: %s", outputDir)
		}
	}

	// Save config only if it's new or ask for confirmation
	if !configExists {
		if err := saveConfig(config, configPath); err != nil {
			log.Fatalf("Failed to save config: %v", err)
		}
		log.Printf("Config created: %s", configPath)
	} else {
		log.Printf("Using existing config: %s", configPath)
		log.Printf("To recreate default config, delete the file and run setup again")
	}

	log.Printf("Setup complete! FIFOs and directories are ready.")
	log.Printf("")
	log.Printf("Next steps:")
	log.Printf("1. Configure your services to write to these FIFO pipes:")
	log.Printf("")

	// Show instructions only for pipes that exist in config
	for _, pipe := range config.Pipes {
		log.Printf("   %s -> %s (type: %s)", pipe.Input, pipe.Output, pipe.Type)

		switch pipe.Type {
		case "nginx-access":
			log.Printf("     Add to /etc/nginx/nginx.conf:")
			log.Printf("     access_log %s;", pipe.Input)
		case "nginx-stream":
			log.Printf("     Add to /etc/nginx/nginx.conf stream block:")
			log.Printf("     access_log %s;", pipe.Input)
		case "xray":
			log.Printf("     Add to /usr/local/etc/xray/config.json:")
			log.Printf(`     "log": {"access": "%s"}`, pipe.Input)
		case "openvpn":
			log.Printf("     Add to OpenVPN config:")
			log.Printf("     log %s", pipe.Input)
		case "wireguard", "amneziawg":
			log.Printf("     Configure systemd to redirect logs:")
			log.Printf("     journalctl -u wg-quick@wg0 -f > %s", pipe.Input)
		case "manual":
			log.Printf("     Configure your application to write logs to:")
			log.Printf("     %s", pipe.Input)
			if pipe.InputTemplate != "" {
				log.Printf("     Expected format: %s", pipe.InputTemplate)
			}
		}
		log.Printf("")
	}

	log.Printf("2. Start the daemon:")
	log.Printf("   obscure start")
	log.Printf("")
	log.Printf("3. Check anonymized logs in the configured output paths")
}
