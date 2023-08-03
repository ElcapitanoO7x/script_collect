# Domain Fuzzing Script

This is a bash script that performs domain fuzzing and scanning for security vulnerabilities using various tools. It collects URLs from different sources, such as Wayback Machine, Google search, and more, and then runs Nuclei templates for security checks on these URLs. The script utilizes parallel processing to speed up the scanning process for multiple domains.

## Prerequisites

Before running the script, make sure you have the following dependencies installed:

- `waybackurls`
- `katana`
- `gau`
- `hakrawler`
- `nuclei`
- `git` (for cloning the required Nuclei templates)
- `go`


## Installation

1. Clone the repository:

```bash
git clone https://github.com/projectdiscovery/fuzzing-templates.git
git clone https://github.com/hithmast/script_collect.git
```

2. Create a `Results` directory to store the output files:

```bash
mkdir Results
```

## Usage

To run the script, provide a file containing a list of domains, with each domain on a separate line. For example, create a file named `domains.txt` with the following content:

```
example.com
test.com
example.org
```

Then, execute the script as follows:

```bash
./collect.sh domains.txt
```

The script will start processing each domain in parallel, collecting URLs, and then performing fuzzing scans using Nuclei templates. The results will be stored in the `Results` directory.

## Note

- The script uses parallel processing to speed up the scans. Adjust the `-j` option in the `parallel` commands to control the number of parallel jobs (default is 4).

- If a domain name contains special characters, they will be replaced with underscores in the output file names.

- The script will check for the existence of temporary files and proceed with fuzzing scans only if URLs are found.

- Ensure that the required tools and Nuclei templates are accessible from your system's PATH.

## Credits

- Script created by ElcapitanoO7x
- Upgraded by hithmast

**Disclaimer:** Please use this script responsibly and only on domains that you have permission to scan. Running security scans on unauthorized targets may be illegal and unethical.
