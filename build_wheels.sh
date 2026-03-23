#!/bin/bash

# Exit script on any error
set -e

# Function to get PEP 440-compliant version
get_pep440_version() {
  local desc
  desc=$(git describe --tags --long)
  local version commits
  version=$(echo "$desc" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-g[0-9a-f]+$/\1/')
  commits=$(echo "$desc" | sed -E 's/^([0-9]+\.[0-9]+\.[0-9]+)-([0-9]+)-g[0-9a-f]+$/\2/')
  if [ "$commits" -eq 0 ]; then
    echo "$version"
  else
    echo "${version}a${commits}"
  fi
}

# Get the new version from git and update pyproject.toml
NEW_VERSION=$(get_pep440_version)
echo "Updating pyproject.toml to version $NEW_VERSION"
poetry version "$NEW_VERSION"

# Build the python package
echo "Building the package with poetry..."
poetry build
