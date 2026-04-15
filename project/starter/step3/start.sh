#!/bin/bash

# Function to handle termination signals
term_handler() {
  echo "Received termination signal. Exiting..."
  exit 0
}

# Trap termination signals
trap 'term_handler' INT TERM

while true; do
  /app/generate_hashed_users
  /app/login
done
