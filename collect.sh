#!/bin/bash

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Check if required commands are available
required_commands=("waybackurls" "katana" "gau" "hakrawler" "nuclei" "git")
for cmd in "${required_commands[@]}"; do
  if ! command_exists "$cmd"; then
    echo "Error: $cmd command not found. Please make sure it is installed and available in your PATH."
    exit 1
  fi
done

# Function to perform fuzzing scans for each domain
perform_fuzzing_scans() {
  domain="$2"
  urls_file="$1"
  NUCLEI_FLAGS="-nh 200 -c 100 -retries 2"

  echo "✨ Start Fuzzing Scans for $domain ✨"

  # Perform fuzzing scans using Nuclei templates

  nuclei -l "$urls_file" $NUCLEI_FLAGS -t "/fuzzing-templates/lfi" -o "Results/$domain-lfi.txt" &
  nuclei -l "$urls_file" $NUCLEI_FLAGS -t "/fuzzing-templates/xss/reflected-xss.yaml" -o "Results/$domain-xss.txt" &
  nuclei -l "$urls_file" $NUCLEI_FLAGS -t "/fuzzing-templates/sqli/error-based.yaml" -o "Results/$domain-sqli.txt" &
  nuclei -l "$urls_file" $NUCLEI_FLAGS -t "/fuzzing-templates/redirect" -o "Results/$domain-redirect.txt" &
  nuclei -l "$urls_file" $NUCLEI_FLAGS -t "/fuzzing-templates/ssrf" -o "Results/$domain-ssrf.txt" &

  # Wait for all fuzzing scans to finish for this domain
  wait

  echo "✨ Fuzzing Scans Completed for $domain.✨"
}

# Function to process each domain
process_domain() {
  domain="$1"
  echo "Processing $domain..."

  # Replace special characters in the domain name with underscores
  sanitized_domain=$(echo "$domain" | tr -d '[:punct:]' | tr '[:upper:]' '[:lower:]' | tr -s ' ' '_')

  # Generate a hash of the sanitized domain name to use as the temporary file prefix
  prefix=$(echo -n "$sanitized_domain" | sha1sum | cut -d' ' -f1)

  # Replace any remaining non-alphanumeric characters in the prefix with underscores
  prefix=$(echo "$prefix" | tr -C '[:alnum:]' '_')

  # Run the tools (waybackurls, katana, gau) in parallel and store their output in temporary files
  waybackurls "$domain" > "$prefix-wayback.txt" &
  katana -u "$domain" > "$prefix-katana.txt" &
  gau "$domain" > "$prefix-gau.txt" &

  # Run hakrawler individually and store its output in a separate file
  echo "$domain" | hakrawler > "$prefix-hakrawler.txt"

  # Wait for all background processes to finish
  wait

  # Check if the temporary files exist before combining their outputs
  if [ -f "$prefix-wayback.txt" ] && [ -f "$prefix-katana.txt" ] && [ -f "$prefix-gau.txt" ] && [ -f "$prefix-hakrawler.txt" ]; then
    # Combine the output from different tools into a single file for each domain
    cat "$prefix-wayback.txt" "$prefix-katana.txt" "$prefix-gau.txt" "$prefix-hakrawler.txt" | sort -u > "Results/$prefix-urls.txt"

    # Check if the URLs file is not empty before proceeding with fuzzing scans
    if [ -s "$prefix-urls.txt" ]; then
      perform_fuzzing_scans "$prefix-urls.txt" "$domain"
    else
      echo "No URLs found for $domain. Skipping fuzzing scans."
    fi

    # Clean up temporary files
    rm -f "$prefix-wayback.txt" "$prefix-katana.txt" "$prefix-gau.txt" "$prefix-hakrawler.txt" "$prefix-urls.txt"
  else
    echo "No data found for $domain. Skipping combining the outputs and fuzzing scans."
  fi

  echo "Done processing $domain."
}
# Export the perform_fuzzing_scans function
export -f perform_fuzzing_scans

echo "✨ Start Domain Processing in Parallel ✨"

# Process each domain in parallel using GNU Parallel
export -f process_domain
cat "$1" | parallel -j 4 process_domain

echo "✨ All Domains Processed. Starting Fuzzing Scans ✨"

# Perform fuzzing scans for each domain in parallel using GNU Parallel
cat "$1" | parallel -j 4 perform_fuzzing_scans

echo "✨ All Fuzzing Scans Completed.✨"
