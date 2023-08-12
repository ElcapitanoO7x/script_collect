# th3Collect0r

[![GitHub](https://img.shields.io/github/license/hithmast/script_collect)](https://github.com/hithmast/script_collect/blob/th3Collect0r/LICENSE)

th3Collect0r is a Go program designed to automate the process of scanning a list of domains for security vulnerabilities using various tools. It combines the outputs of waybackurls, katana, gau, and hakrawler, and performs fuzzing scans using custom Nuclei templates to identify potential security issues.

## Prerequisites

Before running th3Collect0r, ensure you have the following prerequisites:

1. Go installed on your system (tested with Go 1.16).
2. The following tools must be installed and available in your PATH:
   - `waybackurls`
   - `katana`
   - `gau`
   - `hakrawler`
   - `nuclei`

## Installation

1. Clone this repository to your local machine:

   ```bash
   git clone https://github.com/hithmast/script_collect.git
   ```

2. Change into the project directory:

   ```bash
   cd th3Collect0r
   ```

3. Build the program:

   ```bash
   go build th3Collect0r.go
   ```

## Usage

```bash
./th3Collect0r [OPTIONS] FILE_PATH
```

Scan a list of domains for security vulnerabilities using various tools.

Options:

- `-p PARALLEL`: Number of processes to run in parallel. Default: 4.
- `-nf FLAGS`: Custom Nuclei flags to use for all scans.
- `-t TEMPLATE`: Specify the custom Nuclei template for the first scan.
- `-t TEMPLATE`: Specify the custom Nuclei template for the second scan.
- `-t TEMPLATE`: Specify the custom Nuclei template for the third scan.
- `-t TEMPLATE`: Specify the custom Nuclei template for the fourth scan.
- `-t TEMPLATE`: Specify the custom Nuclei template for the fifth scan.
- `-s`: Run th3Collect0r in silent mode. No output will be displayed.
- `-d DOMAIN`: Perform scans on a single target domain.

```
Keep in mind That all template you picked must be inside ~/nuclei-templates
```
## Examples

1. Basic usage with a list of domains in a file:

   ```bash
   ./th3Collect0r -p 4 domains.txt
   ```

2. Run th3Collect0r in silent mode:

   ```bash
   ./th3Collect0r -s -p 4 domains.txt
   ```

3. Perform scans on a single target domain:

   ```bash
   ./th3Collect0r -d example.com
   ```

4. Customize the Nuclei flags and templates:

   ```bash
   ./th3Collect0r -nf "-sa -rl 50" -t /nuclei-templates/path/to/custom-template.yaml domains.txt -f domains.txt
   ```

## License

This project is licensed under the [MIT License](LICENSE).

## Disclaimer

th3Collect0r is provided for educational and research purposes only. Use this program responsibly and ensure you have proper authorization to scan the domains.

## Contributions

Contributions are welcome! If you find any issues or have suggestions for improvements, please open an issue or create a pull request.

## Authors

- Mohamed Ashraf - [Elcapitano07x](https://github.com/ElcapitanoO7x)
- Ali Emara - [Hithmast](https://github.com/hithmast)
