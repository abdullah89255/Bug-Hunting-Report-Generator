# Bug-Hunting-Report-Generator
  Recursive **Bug-Hunting Report Generator** for your Linux/KDE setup.

It will:

* Recursively scan your entire target folder.
* Inventory files and folders.
* Read supported text files.
* Handle large files with a configurable read limit.
* SHA-256 hash files.
* Detect HTTP/HTTPS URLs.
* Detect local HTML files.
* Identify potentially interesting indicators such as API-key-like strings, JWT-like strings, private-key markers, and password assignments **without copying the matched secret values into the report**.
* Generate a searchable HTML report.
* Open the generated report in **Firefox**.
* Optionally open discovered local HTML files in Firefox.
* Optionally open discovered URLs in Firefox after confirmation.
* Avoid automatically making network requests itself.

### Download

[Download `bug_report.py`](sandbox:/mnt/data/bug_report_tool/bug_report.py)

[Download `run_bug_report.sh`](sandbox:/mnt/data/bug_report_tool/run_bug_report.sh)

[Download README](sandbox:/mnt/data/bug_report_tool/README.md)

### On your machine

Put `bug_report.py` somewhere convenient, then run:

```bash
python3 /path/to/bug_report.py --open-report --open-html
```

For the directory shown in your screenshot, for example:

```bash
python3 /path/to/bug_report.py --open-report --open-html
```

The report will be created inside the target directory as:

```text
bug_hunting_report.html
```

### If you also want it to open discovered URLs

```bash
python3 /path/to/bug_report.py --open-report --open-html --open-urls
```

It will ask:

```text
Open ALL discovered URLs in Firefox? [y/N]:
```

I deliberately made URL opening opt-in because a large project can contain hundreds or thousands of URLs, and opening them can contact external systems.

### For your huge dataset

The default maximum amount read from each text file is **8 MB**. You can increase it:

```bash
python3 /path/to/bug_report.py
    --max-read-mb 32 \
    --open-report \
    --open-html
```

For a very large directory where hashing takes too long:

```bash
python3 /path/to/bug_report.py
    --no-hash \
    --open-report
```


