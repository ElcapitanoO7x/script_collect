package main

import (
	"bufio"
	"bytes"
	"fmt"
	"html"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

const toolVersion = "v1"

var templatesPath = ""

func main() {
	// Print tool version and ASCII art
	fmt.Printf("       Th3 Collect0r %s \n", toolVersion)
	fmt.Printf("By : Mohamed Ashraf & Ali Emara\n")
	fmt.Printf("Don't forget to include fuzzing-template/ directory in %s \n", exec.Command("echo $HOME/nuclei-templates"))
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
			"fuzzing-templates/lfi",
			"fuzzing-templates/xss",
			"fuzzing-templates/sqli",
			"fuzzing-templates/redirect",
			"fuzzing-templates/ssrf",
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
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
	fmt.Println("Use --help for a full list of available options.")
}

// Print full usage instructions
func printFullUsage() {
	fmt.Println("Usage: go run th3collect0r.go -f FILE_PATH [OPTIONS]")
	fmt.Println("       go run th3collect0r.go -d DOMAIN")
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
	tempDir, err := os.MkdirTemp("", "scan-temp-")
	if err != nil {
		log.Printf("Error creating temporary directory: %v", err)
		return
	}
	defer os.RemoveAll(tempDir)

	// Declare and initialize the 'urls' map
	urls := make(map[string]bool)

	var wg sync.WaitGroup

	// Run waybackurls
	wg.Add(1)
	go func() {
		defer wg.Done()
		waybackFilePath := filepath.Join(tempDir, "wayback.txt")
		waybackCmd := exec.Command("waybackurls", domainName)
		waybackOutput, err := waybackCmd.Output()
		if err != nil {
			log.Printf("Error running waybackurls for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(waybackFilePath, waybackOutput, 0644)
		if err != nil {
			log.Printf("Error writing wayback output file: %v", err)
			return
		}
		fmt.Printf("Success: waybackurls output written to %s\n", waybackFilePath)
		addURLsFromFile(waybackFilePath, urls)
	}()

	// Run gau
	wg.Add(1)
	go func() {
		defer wg.Done()
		gauFilePath := filepath.Join(tempDir, "gau.txt")
		gauCmd := exec.Command("gau", domainName)
		gauOutput, err := gauCmd.Output()
		if err != nil {
			log.Printf("Error running gau for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(gauFilePath, gauOutput, 0644)
		if err != nil {
			log.Printf("Error writing gau output file: %v", err)
			return
		}
		fmt.Printf("Success: gau output written to %s\n", gauFilePath)
		addURLsFromFile(gauFilePath, urls)
	}()

	// Run katana
	wg.Add(1)
	go func() {
		defer wg.Done()
		katanaFilePath := filepath.Join(tempDir, "katana.txt")
		katanaCmd := exec.Command("katana", "-u", domain, "-d", "6", "-jc")
		var stdout, stderr bytes.Buffer
		katanaCmd.Stdout = &stdout
		katanaCmd.Stderr = &stderr

		if err := katanaCmd.Run(); err != nil {
			log.Printf("Error running katana for %s: %v\nStderr: %s", domainName, err, stderr.String())
			return
		}

		katanaOutput := stdout.Bytes()
		err := os.WriteFile(katanaFilePath, katanaOutput, 0644)
		if err != nil {
			log.Printf("Error writing katana output file: %v", err)
			return
		}
		fmt.Printf("Success: katana output written to %s\n", katanaFilePath)
		addURLsFromFile(katanaFilePath, urls)
	}()

	// Run hakrawler
	wg.Add(1)
	go func() {
		defer wg.Done()
		hakrawlerFilePath := filepath.Join(tempDir, "hakrawler.txt")
		hakrawlerCmd := exec.Command("hakrawler")
		hakrawlerCmd.Stdin = strings.NewReader(domain)
		hakrawlerOutput, err := hakrawlerCmd.Output()
		if err != nil {
			log.Printf("Error running hakrawler for %s: %v", domainName, err)
			return
		}
		err = os.WriteFile(hakrawlerFilePath, hakrawlerOutput, 0644)
		if err != nil {
			log.Printf("Error writing hakrawler output file: %v", err)
			return
		}
		fmt.Printf("Success: hakrawler output written to %s\n", hakrawlerFilePath)
		addURLsFromFile(hakrawlerFilePath, urls)
	}()

	// Wait for all tasks to complete
	wg.Wait()

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

	// Declare and initialize the WaitGroup for Nuclei scans
	var wgNuclei sync.WaitGroup
	semaphoreNuclei := make(chan struct{}, len(templateNames))

	var wgHTML sync.WaitGroup
	semaphoreHTML := make(chan struct{}, len(templateNames))

	for _, templatePath := range templateNames {
		semaphoreNuclei <- struct{}{}
		wgNuclei.Add(1)

		go func(templatePath string) {
			defer wgNuclei.Done()
			defer func() { <-semaphoreNuclei }()
			if err := performNucleiScan(urlsFile, templatePath, domain); err != nil {
				log.Printf("Error performing Nuclei scan for %s with template %s: %v", domainName, templatePath, err)
			} else {
				fmt.Printf("Success: Nuclei scan completed for %s with template %s\n", domainName, templatePath)
			}
		}(templatePath)
		semaphoreHTML <- struct{}{}
		wgHTML.Add(1)

		go func(templatePath string) {
			defer wgHTML.Done()
			defer func() { <-semaphoreNuclei }()
			if err := generateHTMLReport(domain, strings.Fields(templatePath)); err != nil {
				log.Printf("Error Generate HTML for %s with template %s: %v", domainName, templatePath, err)
			} else {
				fmt.Printf("Success: HTML  completed for %s with template %s\n", domainName, templatePath)
			}
		}(templatePath)
	}

	wgNuclei.Wait()
	wgHTML.Wait()

	// Generate HTML report using Nuclei results
	if err := generateHTMLReport(domain, templateNames); err != nil {
		log.Printf("Error generating HTML report for %s: %v", domain, err)
	}

	fmt.Printf("Done processing %s\n", domainName)
}

// Nuclei function
func performNucleiScan(urlsFile, templatePath, domain string) error {
	templateName := filepath.Base(templatePath)
	outputFile := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templateName)

	nucleiCmd := exec.Command("sh", "-c", fmt.Sprintf("nuclei -l %s -t %s -o %s", urlsFile, templatePath, outputFile))
	nucleiCmd.Stdout = os.Stdout
	nucleiCmd.Stderr = os.Stderr

	if err := nucleiCmd.Run(); err != nil {
		return err
	}

	return nil
}
func addURLsFromFile(filePath string, urls map[string]bool) {
	// Open the file and create a scanner.
	file, err := os.Open(filePath)
	if err != nil {
		log.Printf("Error opening file: %v", err)
		return
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)

	// Iterate over the lines in the file.
	for scanner.Scan() {
		// Get the URL from the current line.
		url := scanner.Text()

		// Check if the URL contains a protocol.
		if !strings.Contains(url, "://") {
			// If not, prepend the `https://` protocol.
			url = "https://" + url
		}

		// Add the URL to the map.
		urls[url] = true
	}

	// Check for errors reading the file.
	if err := scanner.Err(); err != nil {
		log.Printf("Error reading file: %v", err)
		return
	}
}

// Generate HTML Function
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

		outputFilePath := fmt.Sprintf("Results/%s_%s_output.txt", sanitizeFileName(domain), templatePath)
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
