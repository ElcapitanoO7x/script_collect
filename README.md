# th3Collect0r

![GitHub](https://img.shields.io/github/license/hithmast/script_collect)

th3Collect0r is a bash script designed to automate the process of scanning a list of domains for security vulnerabilities using various tools. It combines the outputs of waybackurls, katana, gau, and hakrawler, and performs fuzzing scans using custom Nuclei templates to identify potential security issues.

## Prerequisites

Before running the script, ensure you have the following prerequisites:

1. Linux-based system (tested on Ubuntu 20.04).
2. The following tools must be installed and available in your PATH:
   - `waybackurls`
   - `katana`
   - `gau`
   - `hakrawler`
   - `nuclei`
   - `git`
   - `parallel`
3. Proper authorization to perform security scans on the provided domains.

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/hithmast/script_collect/th3Collect0r.git
   ```

2. Change into the project directory:

   ```bash
   cd th3Collect0r
   ```

3. Make the script executable:

   ```bash
   chmod +x th3Collect0r.sh
   ```

## Usage

```bash
./th3Collect0r.sh [OPTIONS] FILE_PATH
```

Scan a list of domains for security vulnerabilities using various tools.

Options:

- `-s`: Silence mode. Run the script in the background.
- `-t PARALLEL`: Number of processes to run in parallel using GNU Parallel. Default: 4.
- `-nf FLAGS`: Custom Nuclei flags to use for all scans.
- `-t1 TEMPLATE`: Specify the custom Nuclei template for the first scan. Default: /fuzzing-templates/lfi
- `-t2 TEMPLATE`: Specify the custom Nuclei template for the second scan. Default: /fuzzing-templates/xss/reflected-xss.yaml
- `-t3 TEMPLATE`: Specify the custom Nuclei template for the third scan. Default: /fuzzing-templates/sqli/error-based.yaml
- `-t4 TEMPLATE`: Specify the custom Nuclei template for the fourth scan. Default: /fuzzing-templates/redirect
- `-t5 TEMPLATE`: Specify the custom Nuclei template for the fifth scan. Default: /fuzzing-templates/ssrf
- `-h`, `--help`: Print this help message and exit.

## Examples

1. Basic usage with a list of domains in a file:

   ```bash
   ./th3Collect0r.sh domains.txt
   ```

2. Run the script in silence mode with 8 parallel processes:

   ```bash
   ./th3Collect0r.sh -s -t 8 domains.txt
   ```

3. Customize the Nuclei flags and templates:

   ```bash
   ./th3Collect0r.sh -nf "-t cves" -t1 /path/to/custom-template.yaml domains.txt
   ```

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

th3Collect0r is provided for educational and research purposes only. Use this script responsibly and ensure you have proper authorization to scan the domains.

## Contributions

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.

## Author

 Mohamed Ashraf - [Elcapitano07x](https://github.com/ElcapitanoO7x)
 Ali Emara - [Hithmast](https://github.com/hithmast)
