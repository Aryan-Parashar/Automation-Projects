#!/bin/bash

# Configuration
CSV_FILE="urls.csv"   # CSV file containing the URLs
MONGO_DB="cms_detection"   # MongoDB database name
MONGO_COLLECTION="technologies"   # MongoDB collection name
WHATWEB_AGGRESSION_LEVEL=3   # Set WhatWeb aggression level

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Check for necessary tools
if ! command_exists whatweb; then
    echo "Error: WhatWeb is not installed."
    exit 1
fi

if ! command_exists mongoimport; then
    echo "Error: MongoDB tools are not installed."
    exit 1
fi

if ! command_exists jq; then
    echo "Error: jq is not installed."
    exit 1
fi

# Ensure MongoDB is running
if ! pgrep -x "mongod" > /dev/null; then
    echo "Error: MongoDB server is not running."
    exit 1
fi

# Remove old MongoDB data (optional, for fresh start)
mongo $MONGO_DB --eval "db.dropDatabase()"

# Read CSV file line by line
while IFS=, read -r url
do
    # Skip empty lines or comments
    [[ -z "$url" || "$url" == \#* ]] && continue

    echo "Scanning $url..."
    
    # Run WhatWeb and parse the output with jq
    output=$(whatweb --aggression $WHATWEB_AGGRESSION_LEVEL --log-json - "$url")
    
    # Check if WhatWeb returned any data
    if [[ -z "$output" ]]; then
        echo "Error: WhatWeb failed to scan $url."
        continue
    fi

    # Extract the relevant information from JSON output
    technologies=$(echo "$output" | jq '.[0] | {URL: .url, IP: .ip, Plugins: .plugins | to_entries | map({(.key): .value | .[]}) | add}')
    
    if [[ -n "$technologies" ]]; then
        # Insert data into MongoDB
        echo "$technologies" | mongoimport --db $MONGO_DB --collection $MONGO_COLLECTION --jsonArray --drop
        echo "Data for $url has been stored in MongoDB."
    else
        echo "No technologies detected for $url."
    fi

done < "$CSV_FILE"

echo "CMS and technology detection complete. Results stored in MongoDB database '$MONGO_DB', collection '$MONGO_COLLECTION'."
