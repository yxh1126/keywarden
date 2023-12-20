#
# Copyright 2023 Yi Huang. All Rights Reserved.
#

import sys
import random

TIMES = 3200
IP_ADDR = '''10.8.50.228'''

CMD_A = '''./gen_sign_client ./test_set/source.hash 1024'''
CMD_B = '''./gen_sign_client ./test_set/source.hash 2048'''


def gen_bash_cmd(times, check):
  cmd = CMD_A
  key_id = str(random.randint(1, 8))

  if check == 'B':
    cmd = CMD_B

  for i in range(times):
    cmdx = cmd + ' ' + key_id + ' ' + IP_ADDR
    print(cmdx + " & \\")


if __name__ == '__main__':
  num = TIMES
  sel = 'A'

  if (len(sys.argv) >= 2):
    try:
      num = int(sys.argv[1])
    except:
      pass

  if (len(sys.argv) >= 3):
    if (sys.argv[2] == 'B'):
      sel = 'B'

  gen_bash_cmd(num, sel)
