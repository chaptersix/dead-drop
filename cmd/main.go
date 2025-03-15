package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/smtp"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"github.com/AlecAivazis/survey/v2"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/nacl/secretbox"
)

type config struct {
	To       string
	Message  string
	Subject  string
	From     string
	Password string
	SMTPHost string
	STMPPort string
}

func (c config) String() string {
	by, _ := json.Marshal(c)
	return string(by)
}

func main() {
	var rootCmd = &cobra.Command{Use: "dd"}
	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Setup Dead Drop configuration",
		Run: func(cmd *cobra.Command, args []string) {
			setup()
		},
	}

	var loadCmd = &cobra.Command{
		Use:   "load",
		Short: "load the config",
		Run: func(cmd *cobra.Command, args []string) {
			cfg, err := loadEncryptedConfig()
			if err != nil {
				fmt.Print("could not load config: ", err.Error())
			}
			fmt.Println(cfg)
		},
	}
	var deleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "delete the config",
		Run: func(cmd *cobra.Command, args []string) {
			delete()
		},
	}
	rootCmd.AddCommand(setupCmd)
	rootCmd.AddCommand(loadCmd)
	rootCmd.AddCommand(deleteCmd)
	rootCmd.Execute()
}

func setup() {

	cfg := config{}
	// Define the questions
	prompt := &survey.Input{
		Message: "Enter recipient email address:",
	}
	survey.AskOne(prompt, &cfg.To)

	prompt = &survey.Input{
		Message: "Enter Subject:",
	}
	survey.AskOne(prompt, &cfg.Subject)

	prompt = &survey.Input{
		Message: "Enter your message:",
	}
	survey.AskOne(prompt, &cfg.Message)

	prompt = &survey.Input{
		Message: "Enter your email address:",
	}
	survey.AskOne(prompt, &cfg.From)

	fmt.Println("\nIf you have 2-Step Verification enabled on your Google account, you need to create an App Password to use here.")

	promptp := &survey.Password{
		Message: "Enter your email password (or app password):",
	}
	survey.AskOne(promptp, &cfg.Password)

	prompt = &survey.Input{
		Message: "Enter SMTP host (e.g., smtp.gmail.com):",
		Default: "smtp.gmail.com",
	}
	survey.AskOne(prompt, &cfg.SMTPHost)

	prompt = &survey.Input{
		Message: "Enter SMTP port (e.g., 587):",
		Default: "587",
	}
	survey.AskOne(prompt, &cfg.STMPPort)

	// Encrypt and store the configuration
	key, err := generateKey()
	if err != nil {
		fmt.Println("Error generating key:", err)
		return
	}
	encryptedCfg, err := encryptConfig(cfg, key)
	if err != nil {
		fmt.Println("Error encrypting config:", err)
		return
	}
	tempFilePath, err := getConfigFilePath()
	if err != nil {
		fmt.Println("Error getting config file path:", err)
		return
	}
	createPathINE(tempFilePath)
	if err != nil {
		fmt.Println("Error creating dir:", err)
		return
	}
	err = saveEncryptedConfig(encryptedCfg, tempFilePath)
	if err != nil {
		fmt.Println("Error saving encrypted config:", err)
		return
	}
	fmt.Println("Encrypted configuration saved to:", tempFilePath)

	_, err = loadEncryptedConfig()
	if err != nil {
		fmt.Println("failed to load the config: ", err.Error())
		return
	}
	fmt.Print("verified the config was saved")
	// Send the email using the collected information
	//err = sendEmail(cfg)
	//if err != nil {
	//	fmt.Printf("Failed to send email: %v\n", err)
	//} else {
	//fmt.Println("Email sent successfully!")
	//}
}

func delete() {
	tempFilePath, _ := getConfigFilePath()
	dir := filepath.Dir(tempFilePath)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Remove(dir)
		if err != nil {
			fmt.Println("could not remove dir: ", dir)

		}
	}
}

// sendEmail sends an email using the provided SMTP configuration and credentials.
func sendEmail(cfg config) error {
	// Set up authentication information.
	auth := smtp.PlainAuth("", cfg.From, cfg.Password, cfg.SMTPHost)

	// Create the email message.
	msg := []byte{}
	msg = fmt.Appendf(msg, "To: %s\r\nSubject: %s\r\n\r\n%s\r\n", cfg.To, cfg.Subject, cfg.Message)

	// Send the email.
	err := smtp.SendMail(cfg.SMTPHost+":"+cfg.STMPPort, auth, cfg.From, []string{cfg.To}, msg)
	return err
}

// generateKey creates a new 32-byte key using a secure random source.
func generateKey() ([32]byte, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return [32]byte{}, err
	}
	uid := getHostUniqueID()
	key := sha256.Sum256([]byte(hostname + uid))
	return key, nil
}

// encryptConfig serializes the config struct to JSON and encrypts it using secretbox.
func encryptConfig(cfg config, key [32]byte) ([]byte, error) {
	configData, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	encrypted := secretbox.Seal(nonce[:], configData, &nonce, &key)
	return encrypted, nil
}

func createPathINE(fp string) error {
	dir := filepath.Dir(fp)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.MkdirAll(dir, 0755) // Creates directory and all parent directories if needed
		if err != nil {
			return err
		}
	}
	return nil
}

// getTempFilePath returns a consistent file path based on the hostname.
func getConfigFilePath() (string, error) {
	hostname, _ := os.Hostname()
	hash := sha256.Sum256([]byte(hostname))
	shortHash := fmt.Sprintf(".%s", removeNonAlpha(base64.URLEncoding.EncodeToString(hash[:])))
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, shortHash, ".dd.jpg"), nil
}

func removeNonAlpha(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.IsLetter(r) {
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// saveEncryptedConfig saves the encrypted configuration data to the specified file.
func saveEncryptedConfig(data []byte, filename string) error {
	return os.WriteFile(filename, data, 0600)
}

// loadEncryptedConfig reads the encrypted configuration file, decrypts its contents,
// and unmarshals it into a config struct.
func loadEncryptedConfig() (config, error) {
	var cfg config
	tempFilePath, err := getConfigFilePath()
	if err != nil {
		return cfg, fmt.Errorf("failed to get config file path: %w", err)
	}
	data, err := os.ReadFile(tempFilePath)
	if err != nil {
		return cfg, fmt.Errorf("failed to read config file: %w", err)
	}
	if len(data) < 24 {
		return cfg, fmt.Errorf("invalid encrypted config data")
	}
	var nonce [24]byte
	copy(nonce[:], data[:24])
	encryptedData := data[24:]
	key, err := generateKey()
	if err != nil {
		return cfg, fmt.Errorf("failed to generate key: %w", err)
	}
	decrypted, ok := secretbox.Open(nil, encryptedData, &nonce, &key)
	if !ok {
		return cfg, fmt.Errorf("decryption failed")
	}
	err = json.Unmarshal(decrypted, &cfg)
	if err != nil {
		return cfg, fmt.Errorf("failed to unmarshal config: %w", err)
	}
	return cfg, nil
}

// GetHostUniqueID returns a stable unique ID per host (OS-specific), or "" if unavailable.
func getHostUniqueID() string {
	var id string
	var err error

	switch runtime.GOOS {
	case "linux":
		id, err = getLinuxMachineID()
	case "windows":
		id, err = getWindowsUUID()
	case "darwin":
		id, err = getDarwinUUID()
	case "freebsd":
		id, err = getFreeBSDUUID()
	case "openbsd":
		id, err = getOpenBSDUUID()
	case "netbsd":
		id, err = getNetBSDUUID()
	default:
		id = ""
	}

	if err != nil {
		fmt.Println("could not get unique id.")
		return ""
	}
	return id
}

// Linux: /etc/machine-id (No elevated permissions required)
func getLinuxMachineID() (string, error) {
	data, err := os.ReadFile("/etc/machine-id")
	if err != nil {
		return "", nil
	}
	return strings.TrimSpace(string(data)), nil
}

// Windows: wmic system UUID (Typically no elevated permissions required)
func getWindowsUUID() (string, error) {
	cmd := exec.Command("wmic", "csproduct", "get", "UUID")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", nil
	}

	lines := strings.Split(out.String(), "\n")
	if len(lines) < 2 {
		return "", nil
	}
	uuid := strings.TrimSpace(lines[1])
	if uuid == "" {
		return "", nil
	}
	return uuid, nil
}

// macOS (Darwin): Hardware UUID via ioreg (No elevated permissions required)
func getDarwinUUID() (string, error) {
	cmd := exec.Command("ioreg", "-rd1", "-c", "IOPlatformExpertDevice")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", nil
	}

	for _, line := range strings.Split(out.String(), "\n") {
		if strings.Contains(line, "IOPlatformUUID") {
			parts := strings.Split(line, "=")
			if len(parts) == 2 {
				uuid := strings.TrimSpace(parts[1])
				return strings.Trim(uuid, `" `), nil
			}
		}
	}
	return "", nil
}

// FreeBSD: /etc/hostid or kenv (Typically no elevated permissions required)
func getFreeBSDUUID() (string, error) {
	if data, err := os.ReadFile("/etc/hostid"); err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	}

	cmd := exec.Command("kenv", "-q", "smbios.system.uuid")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", nil
	}
	uuid := strings.TrimSpace(out.String())
	if uuid == "" {
		return "", nil
	}
	return uuid, nil
}

// OpenBSD: sysctl hw.uuid (Typically no elevated permissions required)
func getOpenBSDUUID() (string, error) {
	cmd := exec.Command("sysctl", "-n", "hw.uuid")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", nil
	}
	uuid := strings.TrimSpace(out.String())
	if uuid == "" {
		return "", nil
	}
	return uuid, nil
}

// NetBSD: sysctl machdep.dmi.system-uuid (Typically no elevated permissions required)
func getNetBSDUUID() (string, error) {
	cmd := exec.Command("sysctl", "-n", "machdep.dmi.system-uuid")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return "", nil
	}
	uuid := strings.TrimSpace(out.String())
	if uuid == "" {
		return "", nil
	}
	return uuid, nil
}
