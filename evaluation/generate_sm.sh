#!/usr/bin/env bash
#
# Example usage:
#   $ chmod +x generate_sm.sh
#   $ ./generate_sm.sh
#   or
#   $ ./generate_sm.sh /path/to/pcapng/dir

########################################
# Script settings
########################################

# 1) Directory containing pcapng files (default: sample_traffics)
PCAP_DIR="${1:-sample_traffics}"

# 2) Options for prett3_syn.py (customize if needed)
PRETT3_URL="https://prett3.com"
DK_OPT="-dk sample_traffics/secrets.keylog"
OK_OPT="-ok secrets.keylog"

# 3) Define available server_version combinations
server_versions=("cdy_n" "cdy_o" "h2o_n" "h2o_o" "ng_n" "ng_o" "ols_n" "ols_o")

########################################
# 0. Preliminary checks and setup
########################################

# Check if PCAP_DIR is valid
if [ ! -d "$PCAP_DIR" ]; then
  echo "The specified directory does not exist: $PCAP_DIR"
  exit 1
fi

# Find all pcapng files in the directory
mapfile -t pcap_files < <(ls -1 "${PCAP_DIR}"/*.pcapng 2>/dev/null)

# If no pcapng files found
if [ ${#pcap_files[@]} -eq 0 ]; then
  echo "No .pcapng files found in: $PCAP_DIR"
  exit 1
fi

########################################
# 1. Display server_version groups
########################################

echo "Select a server_version combination to test all six related files:"
for i in "${!server_versions[@]}"; do
  echo "  $((i+1))) ${server_versions[$i]}"
done

# Prompt user for selection
echo ""
read -p "Enter the number corresponding to your choice: " SELECTED_INDEX

# Validate numeric input
if ! [[ "$SELECTED_INDEX" =~ ^[0-9]+$ ]]; then
  echo "Invalid input. Please enter a number."
  exit 1
fi

# Convert to zero-based index
SELECTED_INDEX=$((SELECTED_INDEX - 1))

# Check if input is within range
if [ "$SELECTED_INDEX" -lt 0 ] || [ "$SELECTED_INDEX" -ge "${#server_versions[@]}" ]; then
  echo "The input number is out of range."
  exit 1
fi

# Store the selected server_version
SELECTED_SERVER_VERSION="${server_versions[$SELECTED_INDEX]}"

########################################
# 2. Find all matching files
########################################

# Extract all pcapng files that match the selected server_version (e.g., *_cdy_n.pcapng)
matching_files=()
for file in "${pcap_files[@]}"; do
  if [[ "$file" == *"_${SELECTED_SERVER_VERSION}.pcapng" ]]; then
    matching_files+=("$file")
  fi
done

# Ensure we found 6 related files
if [ ${#matching_files[@]} -ne 6 ]; then
  echo "Error: Expected 6 matching files for '${SELECTED_SERVER_VERSION}', but found ${#matching_files[@]}."
  exit 1
fi

########################################
# 3. Process each matching file
########################################

for SELECTED_PCAP in "${matching_files[@]}"; do
  FILE_ONLY="$(basename "$SELECTED_PCAP")"
  BASENAME="${FILE_ONLY%.*}"  # remove .pcapng => e.g. ch_n_cdy_o

  RESULT_DIR="result"
  TARGET_RESULT_DIR="${RESULT_DIR}/${BASENAME}"

  # Automatically clear previous results
  if [ -d "${TARGET_RESULT_DIR}" ]; then
    echo "Clearing existing contents in '${TARGET_RESULT_DIR}'..."
    rm -rf "${TARGET_RESULT_DIR:?}/"*
  fi

  mkdir -p "${TARGET_RESULT_DIR}"

  ########################################
  # 4. Run prett3_syn.py and store results
  ########################################

  echo "Running prett3_syn.py on '${FILE_ONLY}'..."

  sudo python3 prett3_syn.py \
    "${PRETT3_URL}" \
    "${SELECTED_PCAP}" \
    ${DK_OPT} \
    ${OK_OPT}

  # Move output files to the target directory
  mv "${RESULT_DIR}"/*.png "${TARGET_RESULT_DIR}" 2>/dev/null
  mv "${RESULT_DIR}"/*.json "${TARGET_RESULT_DIR}" 2>/dev/null

  echo "Output files for '${FILE_ONLY}' have been stored in '${TARGET_RESULT_DIR}'."
done

echo "All tests completed for '${SELECTED_SERVER_VERSION}'."
echo "Done."
