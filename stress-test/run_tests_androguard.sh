#!/bin/bash

run_binary_on_dex_files() {
    # Find all .dex files in the current directory and subdirectories
    local dex_files=$(find . -type f -name "*.dex")

    # Check if any .dex files were found
    if [ -z "$dex_files" ]; then
        echo "No .dex files found"
        return 1
    fi

    echo "Testing androguard analysis with shuriken-dump"
    local successes=()
    local failures=()

    # Run the binary on each .dex file found
    for dex_file in $dex_files; do
        echo "Running python3 ./analyze.py on $dex_file"
        echo "Command: python3 ./analyze.py '$dex_file'"
        # Run the binary and capture any error message
        output=$(python3 ./analyze.py "$dex_file" 2>&1)
        if [ $? -ne 0 ]
        then
            # Add to failures if command failed
            failures+=("$dex_file: $output")
        else
            # Add to successes if command succeeded
            file_size=$(stat -c%s "$dex_file")
            time_taken=$(echo "$output" | tail -n 1)  # Get the last line for the time taken
            successes+=("$dex_file, time: ${time_taken}, file size: ${file_size} bytes")
        fi
    done

    echo "Disassembly results"
    # Display successes
    echo -e "\nFiles that ran successfully:"
    for success in "${successes[@]}"; do
        echo "$success"
    done

    # Display failures with error messages
    echo -e "\nFiles that failed:"
    for failure in "${failures[@]}"; do
        echo "$failure"
    done


    # Return success
    return 0
}

run_binary_on_dex_files
