#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Check if required commands are available
required_commands=("waybackurls" "katana" "gau" "hakrawler" "nuclei" "git" "parallel" "sshpass")
for cmd in "${required_commands[@]}"; do
  if ! command_exists "$cmd"; then
    echo "Error: $cmd command not found. Please make sure it is installed and available in your PATH."
    exit 1
  fi
done

# Function to perform fuzzing scans for each domain
perform_fuzzing_scans() {
  local urls_file="$1"
  local domain="$2"
  local custom_nuclei_flags="${3:-}"

  echo "✨ Start Fuzzing Scans for $domain ✨"

  # Perform fuzzing scans using Nuclei templates with custom flags if provided
  nuclei -l "$urls_file" "$custom_nuclei_flags" -t "$template1" -o "Results/${domain}-${template1_name}.txt" &
  nuclei -l "$urls_file" "$custom_nuclei_flags" -t "$template2" -o "Results/${domain}-${template2_name}.txt" &
  nuclei -l "$urls_file" "$custom_nuclei_flags" -t "$template3" -o "Results/${domain}-${template3_name}.txt" &
  nuclei -l "$urls_file" "$custom_nuclei_flags" -t "$template4" -o "Results/${domain}-${template4_name}.txt" &
  nuclei -l "$urls_file" "$custom_nuclei_flags" -t "$template5" -o "Results/${domain}-${template5_name}.txt" &

  # Wait for all fuzzing scans to finish for this domain
  wait

  echo "✨ Fuzzing Scans Completed for $domain.✨"
}

# Function to process each domain
process_domain() {
  local domain="$1"
  echo "Processing $domain..."

  # Extract the domain name from the URL
  local domain_name="${domain#*://}"

  # Generate a random prefix for the temporary directory name
  local prefix=$(tr -dc 'a-zA-Z0-9' < /dev/urandom | head -c 8)

  # Create temporary directories for storing tool outputs
  local results_dir="Results"
  mkdir -p "$results_dir" || { echo "Error: Unable to create directory $results_dir"; exit 1; }
  local temp_dir=$(mktemp -d "$results_dir/tmp.XXXXXXXXXX") || { echo "Error: Unable to create temporary directory"; exit 1; }

  # Run waybackurls and gau with domain name
  if ! waybackurls "$domain" > "$temp_dir/${prefix}-wayback.txt"; then
    echo "Error: waybackurls failed for $domain_name"
    rm -rf "$temp_dir"
    exit 1
  fi

  if ! gau "$domain" > "$temp_dir/${prefix}-gau.txt"; then
    echo "Error: gau failed for $domain_name"
    rm -rf "$temp_dir"
    exit 1
  fi

  # Run katana with full URL
  if ! katana -u "$domain" > "$temp_dir/${prefix}-katana.txt"; then
    echo "Error: katana failed for $domain"
    rm -rf "$temp_dir"
    exit 1
  fi
  
  # Run hakrawler individually and store its output in a separate file
  if ! echo "$domain" | /usr/bin/hakrawler > "$temp_dir/${prefix}-hakrawler.txt"; then
    echo "Error: hakrawler failed for $domain"
    rm -rf "$temp_dir"
    exit 1
  fi

  # Create a progress bar for each domain
  (pv -n "$file_path" | grep -n "$domain" | pv -l -s $(wc -l < "$file_path") > /dev/null) 2>&1 &

  # Wait for all background processes to finish
  wait

  # Check if the temporary files exist before combining their outputs
  if [ -f "$temp_dir/${prefix}-wayback.txt" ] && [ -f "$temp_dir/${prefix}-katana.txt" ] && [ -f "$temp_dir/${prefix}-gau.txt" ] && [ -f "$temp_dir/${prefix}-hakrawler.txt" ]; then
    # Combine the output from different tools into a single file for each domain
    cat "$temp_dir/${prefix}-wayback.txt" "$temp_dir/${prefix}-katana.txt" "$temp_dir/${prefix}-gau.txt" "$temp_dir/${prefix}-hakrawler.txt" | sort -u > "$results_dir/${prefix}-urls.txt"

    # Check if the URLs file is not empty before proceeding with fuzzing scans
    if [ -s "$results_dir/${prefix}-urls.txt" ]; then
      perform_fuzzing_scans "$results_dir/${prefix}-urls.txt" "$domain" "$custom_nuclei_flags"
    else
      echo "No URLs found for $domain. Skipping fuzzing scans."
    fi

    # Clean up temporary files
    rm -rf "$temp_dir"
  else
    echo "No data found for $domain. Skipping combining the outputs and fuzzing scans."
    rm -rf "$temp_dir"
  fi

  echo "Done processing $domain."
}

# Export the perform_fuzzing_scans function
export -f perform_fuzzing_scans process_domain

# Function to display usage instructions
print_usage() {
  echo "Usage: $0 [OPTIONS] FILE_PATH"
  echo "Scan a list of domains for security vulnerabilities using various tools."
  echo "Options:"
  echo "  -s             Silence mode. Run the script in the background."
  echo "  -t PARALLEL    Number of processes to run in parallel using GNU Parallel. Default: 4."
  echo "  -nf FLAGS      Custom Nuclei flags to use for all scans."
  echo "  -t1 TEMPLATE   Specify the custom Nuclei template for the first scan. Default: /fuzzing-templates/lfi"
  echo "  -t2 TEMPLATE   Specify the custom Nuclei template for the second scan. Default: /fuzzing-templates/xss/reflected-xss.yaml"
  echo "  -t3 TEMPLATE   Specify the custom Nuclei template for the third scan. Default: /fuzzing-templates/sqli/error-based.yaml"
  echo "  -t4 TEMPLATE   Specify the custom Nuclei template for the fourth scan. Default: /fuzzing-templates/redirect"
  echo "  -t5 TEMPLATE   Specify the custom Nuclei template for the fifth scan. Default: /fuzzing-templates/ssrf"
  echo "  -h, --help     Print this help message and exit."
  echo ""
  echo "Note: Make sure you have proper authorization to perform security scans on the provided domains."
}

# Read command-line arguments
file_path=""
silence_mode=""
parallel_processes=""
custom_nuclei_flags=""
template1="/fuzzing-templates/lfi"
template2="/fuzzing-templates/xss/reflected-xss.yaml"
template3="/fuzzing-templates/sqli/error-based.yaml"
template4="/fuzzing-templates/redirect"
template5="/fuzzing-templates/ssrf"

template1_name="lfi"
template2_name="xss"
template3_name="sqli"
template4_name="redirect"
template5_name="ssrf"

while [[ $# -gt 0 ]]; do
  case $1 in
    -s)
      silence_mode="yes"
      ;;
    -t)
      shift
      parallel_processes="$1"
      ;;
    -nf)
      shift
      custom_nuclei_flags="$1"
      ;;
    -t1)
      shift
      template1="$1"
      ;;
    -t2)
      shift
      template2="$1"
      ;;
    -t3)
      shift
      template3="$1"
      ;;
    -t4)
      shift
      template4="$1"
      ;;
    -t5)
      shift
      template5="$1"
      ;;
    -h | --help)
      print_usage
      exit 0
      ;;
    *)
      file_path="$1"
      ;;
  esac
  shift
done

if [ -z "$file_path" ]; then
  echo "Error: Please provide a file containing a list of domains to process."
  print_usage
  exit 1
fi
# Validate input file existence and readability
if [ ! -f "$file_path" ] || [ ! -r "$file_path" ]; then
  echo "Error: File not found or not readable: $file_path"
  exit 1
fi

if [ -n "$silence_mode" ]; then
  # Run the script in background (silence mode)
  echo "✨ Start Domain Processing in Silence Mode ✨"
  cat "$file_path" | parallel -j "${parallel_processes:-4}" -u --bar process_domain {}
else
  echo "✨ Start Domain Processing ✨"
  cat "$file_path" | parallel -j "${parallel_processes:-4}" --bar process_domain {}
fi

echo "✨ All Domains Processed. Starting Fuzzing Scans ✨"
cat "$file_path" | parallel -j "${parallel_processes:-4}" --bar perform_fuzzing_scans {}

echo "✨ All Fuzzing Scans Completed.✨"
