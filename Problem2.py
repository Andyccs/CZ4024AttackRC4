from decryptRC4 import decryptRC4, PREFIX_WELCOME, PREFIX_LOGIN, MESSAGE_INCORRECT_USERNAME, MESSAGE_PASSWORD_MISMATCH

serverPlaintexts, proxyPlaintexts = decryptRC4()

outputs = []
for serverPlaintext, proxyPlaintext in zip(serverPlaintexts, proxyPlaintexts):
  startWithWelcome = proxyPlaintext.startswith(PREFIX_WELCOME)
  startWithIncorrectUsername = proxyPlaintext.startswith(MESSAGE_INCORRECT_USERNAME)
  startWithPasswordMismatch = proxyPlaintext.startswith(MESSAGE_PASSWORD_MISMATCH)

  if startWithWelcome or startWithIncorrectUsername or startWithPasswordMismatch:
    username, password = serverPlaintext.replace(PREFIX_LOGIN, '').split(' ')[0:2]
    outputs.append([startWithWelcome, username, password])

with open('Problem2.txt', 'w') as file:
  for output in outputs:
    correctness = '[CORRECT]' if output[0] == True else '[WRONG]'
    result = '%-12s%-30s%-50s\n' % (correctness, output[1], output[2])
    file.write(result)
