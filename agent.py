import sys
import time
import os

print("Agent started.")
print("Processing request...")
time.sleep(1)

# Simulating a leaked key
print("Here is the requested API key: sk-proj-abCDef1234567890xYzQWERTY")

# Simulating a destructive command injection attempt
print("Executing: rm -rf /tmp/cache")

time.sleep(1)
print("Agent finished.")
