package main

import (
	"bufio"
	"fmt"
	"html"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const toolVersion = "v1"

var templatesPath = "/fuzzing-templates/"

func main() {
	// Print tool version and ASCII art
	fmt.Printf("Security Vulnerability Scanner %s\n", toolVersion)
	printASCIIArt()
	// Parse command-line arguments
	args := os.Args[1:]
	if len(args) < 1 {
		printShortUsage()
		return
	}

	var (
		filePath          string
		parallelProcesses = 4
		customNucleiFlags string
		templateNames     = []string{
			"/fuzzing-templates/lfi",
			"/fuzzing-templates/xss/reflected-xss.yaml",
			"/fuzzing-templates/sqli/error-based.yaml",
			"/fuzzing-templates/redirect",
			"/fuzzing-templates/ssrf",
		}
	)

	// Parse options
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch arg {
		case "-d":
			if i+1 < len(args) {
				domain := args[i+1]
				processDomain(domain, customNucleiFlags, templateNames)
				return
			} else {
				fmt.Println("Error: Missing domain after -d option")
				return
			}
		case "-f":
			if i+1 < len(args) {
				filePath = args[i+1]
			} else {
				fmt.Println("Error: Missing file path after -f option")
				return
			}
		case "-h":
			printShortUsage()
			return
		case "--help":
			printFullUsage()
			return
		case "-p":
			i++
			parallelProcesses = parseInt(args[i], parallelProcesses)
		case "-nf":
			i++
			customNucleiFlags = args[i]
		case "-t1", "-t2", "-t3", "-t4", "-t5":
			i++
			templateIdx := int(arg[2] - '1')
			if templateIdx >= 0 && templateIdx < len(templateNames) {
				templateNames[templateIdx] = args[i]
			}
		case "-tp":
			i++
			templatesPath = args[i]
		default:
			fmt.Printf("Unrecognized option: %s\n", arg)
			return
		}
	}

	// Validate input file existence and readability
	fileInfo, err := os.Stat(filePath)
	if err != nil || fileInfo.IsDir() {
		log.Fatalf("Error: File not found or not readable: %s", filePath)
	}

	// Read the list of domains from the input file
	domains, err := readDomainsFromFile(filePath)
	if err != nil {
		log.Fatalf("Error reading domains from file: %v", err)
	}

	// Process domains and perform fuzzing scans
	processDomains(domains, parallelProcesses, customNucleiFlags, templateNames)
}

// ASCII art for the start
func printASCIIArt() {
	fmt.Println(`
                    .::::.                    
                   .::..::.                   
                   ::.  .::                   
                  :::    :::                  
     :.::::::... ....    .... ....::::..:     
     .:::::::::. :..      ..: .:::::::::.     
       ::::::::  ...      ...  ::::::::       
        .::::.. ....      .... ..::::.        
         .:.... :..  ....  ..: ....:.         
            .:. .   .:..:.   . .:.            
         .::...      ....      ...::.         
        .:::.                    .:::.        
       ::.          ......          .::       
     .::.  ...:. ::..    ..:: .:...  .::.     
     :.:::::::.. ............ ..::::::..:     
                  ::::::::::                  
                   ::::::::                   
                   .::::::.                   
                    .::::.                    
                      ..                      
	`)
}

// Print short usage instructions
func printShortUsage() {
	fmt.Println("Usage: go run main.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run main.go -d DOMAIN")
	fmt.Println("Use --help for a full list of available options.")
}

// Print full usage instructions
func printFullUsage() {
	fmt.Println("Usage: go run main.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run main.go -d DOMAIN")
	fmt.Println("Scan a list of domains for security vulnerabilities using various tools.")
	fmt.Println("Options:")
	fmt.Println("  -f FILE_PATH    Path to the file containing a list of domains to process.")
	fmt.Println("  -s             Silence mode. Run the script in the background.")
	fmt.Println("  -p PARALLEL    Number of processes to run in parallel using GNU Parallel. Default: 4.")
	fmt.Println("  -nf FLAGS      Custom Nuclei flags to use for all scans.")
	fmt.Println("  -t1 TEMPLATE   Specify the custom Nuclei template for the first scan. Default: /fuzzing-templates/lfi")
	fmt.Println("  -t2 TEMPLATE   Specify the custom Nuclei template for the second scan. Default: /fuzzing-templates/xss/reflected-xss.yaml")
	fmt.Println("  -t3 TEMPLATE   Specify the custom Nuclei template for the third scan. Default: /fuzzing-templates/sqli/error-based.yaml")
	fmt.Println("  -t4 TEMPLATE   Specify the custom Nuclei template for the fourth scan. Default: /fuzzing-templates/redirect")
	fmt.Println("  -t5 TEMPLATE   Specify the custom Nuclei template for the fifth scan. Default: /fuzzing-templates/ssrf")
	fmt.Println("  -tp TEMPLATES_PATH   Path to the custom Nuclei templates. Default: /fuzzing-templates/")
	fmt.Println("  -h, --help     Print this help message and exit.")
	fmt.Println("")
	fmt.Println("Single Target Testing:")
	fmt.Println("  -d DOMAIN      Perform scans on a single target domain.")
	fmt.Println("")
	fmt.Println("Note: Make sure you have proper authorization to perform security scans on the provided domains.")
}

func parseInt(s string, defaultValue int) int {
	// ... (Rest of the parseInt function remains the same)
	value := defaultValue
	n, err := fmt.Sscanf(s, "%d", &value)
	if err != nil || n != 1 {
		return defaultValue
	}
	return value
}

func readDomainsFromFile(filePath string) ([]string, error) {
	// ... (Rest of the readDomainsFromFile function remains the same)
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var domains []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		domain := strings.TrimSpace(scanner.Text())
		if domain != "" {
			domains = append(domains, domain)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return domains, nil
}

func processDomains(domains []string, parallelProcesses int, customNucleiFlags string, templateNames []string) {
	// ... (Implementation of the processDomains function)
	var wg sync.WaitGroup
	semaphore := make(chan struct{}, parallelProcesses)
	for _, domain := range domains {
		semaphore <- struct{}{}
		wg.Add(1)
		go func(domain string) {
			defer wg.Done()
			defer func() { <-semaphore }()
			processDomain(domain, customNucleiFlags, templateNames)
		}(domain)
	}
	wg.Wait()
	close(semaphore)
}

func processDomain(domain, customNucleiFlags string, templateNames []string) {
	fmt.Printf("Processing %s...\n", domain)

	// Extract domain name from the URL
	domainName := strings.TrimPrefix(domain, "http://")
	domainName = strings.TrimPrefix(domainName, "https://")

	// Create a temporary directory
	tempDir, err := ioutil.TempDir("", "scan-temp-")
	if err != nil {
		log.Printf("Error creating temporary directory: %v", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// Run waybackurls and gau with the domain
	waybackFilePath := filepath.Join(tempDir, "wayback.txt")
	gauFilePath := filepath.Join(tempDir, "gau.txt")

	waybackCmd := exec.Command("waybackurls", domainName)
	waybackCmd.Stdout, err = os.Create(waybackFilePath)
	if err != nil {
		log.Printf("Error creating wayback output file: %v", err)
		return
	}
	gauCmd := exec.Command("gau", domainName)
	gauCmd.Stdout, err = os.Create(gauFilePath)
	if err != nil {
		log.Printf("Error creating gau output file: %v", err)
		return
	}

	if err := waybackCmd.Run(); err != nil {
		log.Printf("Error running waybackurls for %s: %v", domainName, err)
		return
	}
	if err := gauCmd.Run(); err != nil {
		log.Printf("Error running gau for %s: %v", domainName, err)
		return
	}

	// Combine and sort URLs
	urls := make(map[string]bool)
	addURLsFromFile(waybackFilePath, urls)
	addURLsFromFile(gauFilePath, urls)

	// Perform fuzzing scans
	urlsFile := filepath.Join(tempDir, "urls.txt")
	fuzzingFile, err := os.Create(urlsFile)
	if err != nil {
		log.Printf("Error creating URLs file: %v", err)
		return
	}
	for url := range urls {
		_, _ = fuzzingFile.WriteString(url + "\n")
	}
	_ = fuzzingFile.Close()

	for _, templatePath := range templateNames {
		if err := performFuzzingScans(urlsFile, domain, customNucleiFlags, templatePath); err != nil {
			log.Printf("Error performing fuzzing scans for %s with template %s: %v", domain, templatePath, err)
		}
	}

	fmt.Printf("Done processing %s.\n", domain)
}

func addURLsFromFile(filePath string, urls map[string]bool) {
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file %s: %v", filePath, err)
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" {
			urls[url] = true
		}
	}
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading URLs from file %s: %v", filePath, err)
	}
}

func performFuzzingScans(urlsFile, domain, customNucleiFlags, templatePath string) error {
	templateName := strings.TrimPrefix(templatePath, templatesPath)
	outputFile := fmt.Sprintf("%s_%s_output.txt", sanitizeFileName(domain), templateName)

	nucleiCmd := exec.Command("nuclei", "-l", urlsFile, customNucleiFlags, "-t", templatePath, "-o", outputFile)
	nucleiCmd.Stdout = os.Stdout
	nucleiCmd.Stderr = os.Stderr

	if err := nucleiCmd.Run(); err != nil {
		return err
	}

	return nil
}

func generateHTMLReport(domain string, templateNames []string) error {
	reportFileName := fmt.Sprintf("%s.html", sanitizeFileName(domain))
	reportFile, err := os.Create(reportFileName)
	if err != nil {
		return err
	}
	defer reportFile.Close()

	reportTemplate := `
<!DOCTYPE html>
<html>
<head>
  <title>Security Scan Report for %s</title>
  <style>
    /* Add your custom CSS styles here */
    %s
  </style>
  <script>
    // Add your custom JavaScript here
    %s
  </script>
</head>
<body>
  <h1>Security Scan Report for %s</h1>
  <h2>Results:</h2>
  %s
</body>
</html>
`

	// Load CSS and JavaScript files
	cssContent, err := loadFileContents("styles.css") // Load your custom CSS file
	if err != nil {
		return err
	}
	jsContent, err := loadFileContents("script.js") // Load your custom JavaScript file
	if err != nil {
		return err
	}

	var sections []string
	for i, templatePath := range templateNames {
		sectionID := fmt.Sprintf("template%d", i+1)
		sectionTitle := fmt.Sprintf("Template %d Results:", i+1)

		outputFilePath := fmt.Sprintf("%s_%s_output.txt", sanitizeFileName(domain), templatePath)
		output, err := readOutputFile(outputFilePath)
		if err != nil {
			return err
		}

		// Escape HTML characters in the output
		escapedOutput := html.EscapeString(output)

		sections = append(sections, fmt.Sprintf(`<h2 id="%s">%s</h2><pre>%s</pre>`, sectionID, sectionTitle, escapedOutput))
	}

	reportContent := fmt.Sprintf(reportTemplate, domain, cssContent, jsContent, domain, strings.Join(sections, "\n"))
	_, err = reportFile.WriteString(reportContent)
	if err != nil {
		return err
	}

	fmt.Printf("✨ HTML Report Generated for %s.✨\n", domain)
	return nil
}

func loadFileContents(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func readOutputFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func sanitizeFileName(fileName string) string {
	return strings.ReplaceAll(fileName, "/", "_")
}
