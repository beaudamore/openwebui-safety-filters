#!/usr/bin/env python3
"""Test ClamAV exactly like the filter does"""
import clamd
import os

# Get directory of this script
script_dir = os.path.dirname(os.path.abspath(__file__))
test_file = os.path.join(script_dir, 'eicar_test.txt')

# Connect to ClamAV
cd = clamd.ClamdNetworkSocket(host='localhost', port=3310, timeout=30.0)

# Test connection
print("✓ Ping:", cd.ping())
print("✓ Version:", cd.version())

# Create EICAR test file
with open(test_file, 'w') as f:
    f.write('X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*')

print(f"\n✓ Created test file: {test_file}")

# Scan it
print(f"Scanning {test_file}...")
result = cd.scan(test_file)
print("Result:", result)

if result is None:
    print("✓ File is CLEAN")
elif test_file in result:
    status, virus_name = result[test_file]
    if status == "FOUND":
        print(f"✗ VIRUS DETECTED: {virus_name}")
        
# Cleanup
os.remove(test_file)
print(f"\n✓ Cleaned up test file")
