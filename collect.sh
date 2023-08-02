#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Check if required commands are available
required_commands=("waybackurls" "katana" "gau" "hakrawler" "nuclei")
for cmd in "${required_commands[@]}"; do
  if ! command_exists "$cmd"; then
    echo "Error: $cmd command not found. Please make sure it is installed and available in your PATH."
    exit 1
  fi
done


# Function to process each domain
process_domain() {
  domain="$1"
  echo "Processing $domain..."

  # Combine the output from different tools into a single file for each domain
  { waybackurls "$domain"; katana -u "$domain"; gau "$domain"; hakrawler <<< "$domain"; } | sort -u > "$domain-urls.txt"

  echo "Done processing $domain."
}


# Function to perform fuzzing scans for each domain
perform_fuzzing_scans() {
  domain="$1"
  NUCLEI_FLAGS="-nh 200 -c 100 -retries 2"

  echo "✨ Start Fuzzing Scans for $domain ✨"

  # Perform fuzzing scans using Nuclei templates
  nuclei -l "$domain-urls.txt" $NUCLEI_FLAGS -t "/bughunter/fuzzing-templates/lfi" -o "$domain-lfi.txt" &
  nuclei -l "$domain-urls.txt" $NUCLEI_FLAGS -t "/bughunter/fuzzing-templates/xss/reflected-xss.yaml" -o "$domain-xss.txt" &
  nuclei -l "$domain-urls.txt" $NUCLEI_FLAGS -t "/bughunter/fuzzing-templates/sqli/error-based.yaml" -o "$domain-sqli.txt" &
  nuclei -l "$domain-urls.txt" $NUCLEI_FLAGS -t "/bughunter/fuzzing-templates/redirect" -o "$domain-redirect.txt" &
  nuclei -l "$domain-urls.txt" $NUCLEI_FLAGS -t "/bughunter/fuzzing-templates/ssrf" -o "$domain-ssrf.txt" &

  # Wait for all fuzzing scans to finish for this domain
  wait

  echo "✨ Fuzzing Scans Completed for $domain.✨"
}

# Main script starts here

# Check if argument is provided
if [[ -z "$1" ]]; then
  echo "Usage: $0 [domain|domain.txt]"
  exit 1
fi

# Check if argument is a file or a single domain
if [[ -f "$1" ]]; then
  domains=$(cat "$1")
else
  domains="$1"
fi

echo "✨ Start Domain Processing in Parallel ✨"

# Process each domain in parallel using GNU Parallel
export -f process_domain
echo "$domains" | parallel -j 4 process_domain

echo "✨ All Domains Processed. Starting Fuzzing Scans ✨"

# Perform fuzzing scans for each domain in parallel using GNU Parallel
export -f perform_fuzzing_scans
echo "$domains" | parallel -j 4 perform_fuzzing_scans

echo "✨ All Fuzzing Scans Completed.✨"
