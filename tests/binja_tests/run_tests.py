#!/usr/bin/env python3

import os
import json
import tempfile
import subprocess
from multiprocessing import Pool


def run_test(test):
  with tempfile.TemporaryDirectory() as workdir:

    output = ""

    try:
      # Copy files into temporary directory
      for file in test["files"]:
        subprocess.run(["cp", file, workdir])

      # Run setup commands
      for cmd in test["setup_commands"]:
        output += cmd + "\n"
        output += subprocess.check_output(cmd.split(" "), cwd=workdir, stderr=subprocess.STDOUT).decode("charmap")

      # Run test command
      output += test["test_command"] + "\n"
      output = subprocess.check_output(test["test_command"], cwd=workdir, stderr=subprocess.STDOUT, shell=True).decode("charmap")

    except subprocess.CalledProcessError as e:  # If any of the terminal commands fail
      return (False, test["name"], output + e.output.decode("charmap"))

    if output == test["expected_output"]:
      return (True, test["name"])
    else:
      return (False, test["name"],
        "Output didn't match:\n" +
        f"  Expected:  '{test['expected_output']}'\n" +
        f"  Generated: '{output}'\n")


if __name__ == '__main__':
  with open('tests.json') as f:
    tests = json.load(f)

  with Pool(processes=os.cpu_count()) as pool:
    test_data = pool.map(run_test, tests)

  # Processes data
  passed = []
  failed = []
  for test in test_data:
    if test[0]:
      passed.append(test)
    else:
      failed.append(test)

  # Display data
  print("Tests passed:")
  if len(passed) == 0:
    print("  None")
  else:
    for test in sorted(passed):
      print("  " + test[1])

  print("\nTests failed:")
  if len(failed) == 0:
    print("  None\n")
  else:
    for test in sorted(failed):
      print(f"  {test[1]}:")
      for line in test[2].split("\n"):
        print("    " + line)

  print(f"{len(passed)} out of {len(test_data)} tests passed ({len(passed)/len(test_data):.1%}).") 