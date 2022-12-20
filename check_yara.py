import os
import sys
from pathlib import Path
import yara
from dotenv import load_dotenv

load_dotenv()

flag = os.getenv('FLAG')
argc = len(sys.argv)
if argc < 2:
    print("Usage: ./check_yara <rulefile>")
    exit()

rulefile = sys.argv[1]
if not Path(rulefile).exists():
    print("File not found")
    print("Usage: ./check_yara <rulefile>")
    exit()

try:
    rules = yara.compile(filepath=rulefile)
except yara.SyntaxError as e:
    print(str(e))
    exit()
except:
    print("yara compile error")
    exit()

matches = rules.match(data="""
    #!/bin/bash
    echo Hello
""")


if len(matches) > 0:
    print('mathced rule:')
    print(matches)
    print()
    print('flag is ' + flag)
    print('Congratulations!')
else:
    print('No match')