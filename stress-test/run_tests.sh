#!/bin/bash

build_and_get_binary_path() {
  local current_dir=$(pwd)
  cd ..
  local build_dir="build"
  cmake -S . -B $build_dir -DCMAKE_BUILD_TYPE=Release > /dev/null 2> /dev/null
  cmake --build $build_dir -j > /dev/null 2> /dev/null

  if [ $? -ne 0 ]; then
        echo "Build failed"
        return 1
  fi

  local binary_name="shuriken-dump"

  # Find the binary in the build directory
  local binary_path=$(find $(pwd)/${build_dir}/ -type f -name $binary_name)

    # Check if the binary was found
    if [ -z "$binary_path" ]; then
        echo "Binary not found"
        return 1
    fi

    # Return to the original directory
    cd $current_dir

    # Output the path to the binary
    echo $binary_path

    # Return success
    return 0
}

run_binary_on_dex_files() {
  # Build the project and get the binary path
  local binary_path=$(build_and_get_binary_path)

  # Check if the build was successful
    if [ $? -ne 0 ]; then
        echo "Failed to build the project"
        return 1
    fi

    # Find all .dex files in the current directory and subdirectories
    local dex_files=$(find . -type f -name "*.dex")

    # Check if any .dex files were found
    if [ -z "$dex_files" ]; then
        echo "No .dex files found"
        return 1
    fi


    echo "Testing Shuriken parser with Shuriken Dump"
    # Initialize arrays to keep track of successes and failures
    local successes=()
    local failures=()

    # Run the binary on each .dex file found
    for dex_file in $dex_files; do
        echo "Running $binary_path on $dex_file"
        echo "Command: $binary_path '$dex_file' -c -f -m -T"
        # Run the binary and capture any error message
        output=$($binary_path "$dex_file" -c -f -m -T 2>&1)
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

    echo "Parsing results"
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


    echo "Testing Shuriken disassembler with shuriken-dump"
    local successes=()
    local failures=()

    # Run the binary on each .dex file found
        for dex_file in $dex_files; do
            echo "Running $binary_path on $dex_file"
            echo "Command: $binary_path '$dex_file' -c -m -D -T"
            # Run the binary and capture any error message
            output=$($binary_path "$dex_file" -c -m -D -T 2>&1)
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
