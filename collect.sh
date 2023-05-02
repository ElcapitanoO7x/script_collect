#!/bin/bash

# check if argument is provided
if [[ -z "$1" ]]; then
  echo "Usage: $0 [domain|domain.txt]"
  exit 1
fi

# check if argument is a file or a single domain
if [[ -f "$1" ]]; then
  domains=$(cat "$1")
else
  domains="$1"
fi

# loop through each domain
for domain in $domains; do
  echo "Processing $domain..."

  # use waybackurls to find URLs from the Wayback Machine
  waybackurls "$domain" >> urls.txt

  # use katana to find URLs from other sources
  katana -u "$domain" -o urls.txt

  # use gau to find URLs from Google and other search engines
  gau "$domain" >> urls.txt

  # use Hackrawler to find URLs from other sources
  cat "$domain" | Hackrawler >> urls.txt

  # sort and filter unique entries
  sort -u urls.txt > "$domain-urls.txt"

  # clean up
  rm urls.txt
done

echo "Done."

NUCELI_FLAGS=" -nh -c 100 -retries 2"

echo "✨ Start Fuzzing Scan for Endpoints ✨"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//lfi" -o "$lfi.txt" 
echo "✅ Done with LFI."
echo -e "\e[31m======================================\e[0m"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//xss/reflected-xss.yaml" -o "$xss.txt" 
echo "✅ Done with XSS."
echo -e "\e[31m======================================\e[0m"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//sqli/error-based.yaml" -o "$sqli.txt" 
echo "✅ Done with SQLi."
echo -e "\e[31m======================================\e[0m"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//redirect" -o "$redirect.txt" 
echo "✅ Done with Redirects."
echo -e "\e[31m======================================\e[0m"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//ssrf" -o "$ssrf.txt" 
echo "✅ Done with SSRF."
echo -e "\e[31m======================================\e[0m"

nuclei -l "$domain-urls.txt" $NUCELI_FLAGS -t "$/bughunter/fuzzing-templates//ssti" -o "$ssti.txt" 
echo "✅ Done with SSTI."
echo -e "\e[31m======================================\e[0m"