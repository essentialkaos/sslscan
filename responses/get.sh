#!/bin/bash

################################################################################

API_ANALYZE="https://api.ssllabs.com/api/v4/analyze"
API_DETAILS="https://api.ssllabs.com/api/v4/getEndpointData"
EMAIL="jdoe@someoraganizationemail.com"

################################################################################

main() {
  local output_dir="${1:-.}"
  local version status endpoint

  version=$(curl -s --header "email: $EMAIL" "$API_ANALYZE?host=essentialkaos.com" | jq '"v4-" + .engineVersion + "-" + .criteriaVersion' | tr -d '"')

  echo "Current API version: $version"

  if [[ -e "$output_dir/$version.json" ]] ; then
    echo "Data for this version already saved"
    exit 0
  fi

  while : ; do
    status=$(curl -s --header "email: $EMAIL" "$API_ANALYZE?host=essentialkaos.com" | jq '.status' | tr -d '"')

    if [[ "$status" != "READY" ]] ; then
      sleep 5
      continue
    fi

    endpoint=$(curl -s --header "email: $EMAIL" "$API_ANALYZE?host=essentialkaos.com" | jq '.endpoints[0].ipAddress' | tr -d '"')

    curl -s --header "email: $EMAIL" "$API_DETAILS?host=essentialkaos.com&s=$endpoint" | jq '.' > "$output_dir/$version.json"
    echo -e "" >> "$output_dir/$version.json"

    echo "Data saved as $output_dir/$version.json"

    exit 0
  done
}

################################################################################

main $@
