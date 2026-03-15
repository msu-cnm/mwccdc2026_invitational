Team 7
To: MWCCDC Management Team
From: Blue Team
Date: 2/7/2026
Subject: 08 SVRA11T Update Startup Files

## Purpose
This memo serves to document the blue team's response to Inject 08 SVRA11T Update Startup Files. It will provide a clear record of any actions taken to ensure alignment with the operational objectives and goals of the stakeholders involved.

## Executive Summary
As tasked in inject 07 CRYP09T File System Integrity Script, we designed scripts that run against a directory, provided as a parameter, and generate a database of hash signatures per file and  The second script is intended to run every 5 minutes and compare the current list of files and their signature hashes against the database that the first script generated. This memo is discussing the deployment of these scripts
## Response
The blue team implemented the following measures:
- Delivered scripts to Team member 4
- Ran Script Actions successfully

## Action Items
### **Task 1:** Scripts Developed
Assigned to: Team Member 1, 2/7/2026
```
#!/bin/bash

# Check if a directory was provided as an argument
TARGET_DIR=$1
DB_NAME="File System Integrity Database"
DB_PATH="$TARGET_DIR/$DB_NAME"

if [ -z "$TARGET_DIR" ]; then
    echo "Usage: $0 /path/to/directory"
    exit 1
fi

# Ensure the target directory exists
if [ ! -d "$TARGET_DIR" ]; then
    echo "Error: Directory $TARGET_DIR does not exist."
    exit 1
fi

# --- Phase 1: Check if Database exists to determine Mode ---
if [ ! -f "$DB_PATH" ]; then
    echo "Initializing Database for: $TARGET_DIR"
    
    # --- Phase 2: Create the Baseline ---
    # find: searches for files only (-type f)
    # xargs: passes file names to sha256sum
    # Redirection (>): saves the output into our DB file
    find "$TARGET_DIR" -type f -not -name "$DB_NAME" -print0 | xargs -0 sha256sum > "$DB_PATH"
    
    echo "Baseline created successfully in $DB_PATH."
else
    echo "Checking integrity against baseline..."
    
    # --- Phase 3: Compare Current State to Baseline ---
    # We use 'sha256sum --check' to verify existing files.
    # --status: don't output anything, we'll handle the reporting.
    
    TMP_REPORT=$(mktemp)
    
    # Verify existing files in the database
    sha256sum --check "$DB_PATH" --status 2>/dev/null
    if [ $? -eq 0 ]; then
        echo "[ OK ] No existing files have been modified."
    else
        echo "[ WARNING ] File modifications detected!"
        # Show specifically which files failed the check
        sha256sum --check "$DB_PATH" 2>&1 | grep "FAILED"
    fi

    # --- Phase 4: Identify Added or Deleted Files ---
    # Generate a fresh list of current files for comparison
    CURRENT_SCAN=$(mktemp)
    find "$TARGET_DIR" -type f -not -name "$DB_NAME" -print0 | xargs -0 sha256sum > "$CURRENT_SCAN"

    # Compare the filenames (ignoring hashes) between DB and current scan
    # Added files:
    echo "--- New Files Added ---"
    comm -13 <(awk '{print $2}' "$DB_PATH" | sort) <(awk '{print $2}' "$CURRENT_SCAN" | sort)
    
    # Deleted files:
    echo "--- Files Deleted ---"
    comm -23 <(awk '{print $2}' "$DB_PATH" | sort) <(awk '{print $2}' "$CURRENT_SCAN" | sort)

    # Clean up temp files
    rm "$TMP_REPORT" "$CURRENT_SCAN"
fi
```
```
#!/bin/bash

# --- Configuration ---
# List the directories you want to monitor here, separated by spaces.
WATCH_DIRS=("/etc" "/bin" "/sbin" "/var/www/html")
DB_NAME="File System Integrity Database"

# --- Function to log to Syslog ---
# This sends an alert to /var/log/syslog (or /var/log/messages)
log_alert() {
    local message="$1"
    # 'logger' is the standard CLI tool for system logging
    # -p local0.crit sets a high priority alert
    # -t FIM_MONITOR adds a tag for easy searching
    logger -p local0.crit -t FIM_MONITOR "$message"
}

# --- Main Monitoring Loop ---
for DIR in "${WATCH_DIRS[@]}"; do
    DB_PATH="$DIR/$DB_NAME"

    # 1. Skip if the database doesn't exist yet
    if [ ! -f "$DB_PATH" ]; then
        log_alert "Check failed: No database found in $DIR. Run check_integrity.sh first."
        continue
    fi

    # 2. Check for Modified Files (Hash Mismatch)
    # We capture only the failures
    MODIFIED=$(sha256sum --check "$DB_PATH" 2>&1 | grep "FAILED")
    
    if [ ! -z "$MODIFIED" ]; then
        while read -r line; do
            log_alert "MODIFICATION DETECTED: $line in directory $DIR"
        done <<< "$MODIFIED"
    fi

    # 3. Identify Added and Deleted Files
    # Generate a temporary snapshot of current files
    CURRENT_SCAN=$(mktemp)
    find "$DIR" -type f -not -name "$DB_NAME" -print0 | xargs -0 sha256sum > "$CURRENT_SCAN"

    # Compare filenames using the 'comm' utility
    # Added files (present in current scan but not in DB)
    ADDED=$(comm -13 <(awk '{print $2}' "$DB_PATH" | sort) <(awk '{print $2}' "$CURRENT_SCAN" | sort))
    for file in $ADDED; do
        log_alert "NEW FILE DETECTED: $file in $DIR"
    done

    # Deleted files (present in DB but not in current scan)
    DELETED=$(comm -23 <(awk '{print $2}' "$DB_PATH" | sort) <(awk '{print $2}' "$CURRENT_SCAN" | sort))
    for file in $DELETED; do
        log_alert "FILE MISSING: $file from $DIR"
    done

    # Cleanup temp file for this iteration
    rm "$CURRENT_SCAN"
done
```
### **Task 2:** Script Deployed
Assigned to: Team Member 4, 2/7/2026
Team member still in process of deployment
## Conclusion
In response to Inject 08 SVRA11T Update Startup Files, the team responded promptly by quickly developing and deploying start up scripts. Doing so has strengthened the environment and ensured that we have up to date and consistent logs. We will continue to communicate any updates regarding this matter to ensure operations are maintained and all changes reflect the needs and wants of stakeholders and the company.

Best regards,
Blue Team 7