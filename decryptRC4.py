import copy
import codecs

PREFIX_LOGIN = 'LOGIN '
PREFIX_MESSAGE = 'MESSAGE '
PREFIX_WELCOME = 'WELCOME '
PREFIX_REPLY_MESSAGE = 'REPLY MESSAGE '

LENGTH_OF_MESSAGE = 128


def addSpacesTillMaxLength(message):
  return message + ' ' * (LENGTH_OF_MESSAGE - len(message))


MESSAGE_INCORRECT_USERNAME = addSpacesTillMaxLength('INCORRECT USERNAME')
MESSAGE_PASSWORD_MISMATCH = addSpacesTillMaxLength('PASSWORD MISMATCH')

BYTES_PREFIX_LOGIN = bytearray(PREFIX_LOGIN, encoding='utf-8')
BYTES_PREFIX_MESSAGE = bytearray(PREFIX_MESSAGE, encoding='utf-8')
BYTES_PREFIX_WELCOME = bytearray(PREFIX_WELCOME, encoding='utf-8')
BYTES_PREFIX_REPLY_MESSAGE = bytearray(PREFIX_REPLY_MESSAGE, encoding='utf-8')
BYTES_MESSAGE_INCORRECT_USERNAME = bytearray(MESSAGE_INCORRECT_USERNAME, encoding='utf-8')
BYTES_MESSAGE_PASSWORD_MISMATCH = bytearray(MESSAGE_PASSWORD_MISMATCH, encoding='utf-8')


def decryptRC4(clienEncryptedLogFile='ClientLogEnc.dat', serverEncryptedLogFile='ServerLogEnc.dat'):
  proxyEncryptedMessage = None
  serverEncryptedMessage = None

  with open(clienEncryptedLogFile, 'rb') as f:
    proxyEncryptedMessage = f.read()
    proxyEncryptedMessage = bytearray(proxyEncryptedMessage)

  with open(serverEncryptedLogFile, 'rb') as f:
    serverEncryptedMessage = f.read()
    serverEncryptedMessage = bytearray(serverEncryptedMessage)

  # XOR the ciphertexts
  ciphertextXORarray = [
      proxyByte ^ serverByte
      for proxyByte, serverByte in zip(proxyEncryptedMessage, serverEncryptedMessage)
  ]

  # Reshape the array to 30 * 128
  ciphertextXORarray = reshapeCipherTextArray(
      ciphertextXORarray, \
      int(len(ciphertextXORarray) / LENGTH_OF_MESSAGE), \
      LENGTH_OF_MESSAGE)

  # length of proxyPlaintext and serverPlaintext is len(ciphertextXORarray) / LENGTH_OF_MESSAGE
  proxyPlaintext = ["" for i in range(len(ciphertextXORarray))]
  serverPlaintext = ["" for i in range(len(ciphertextXORarray))]

  for index, ciphers in enumerate(ciphertextXORarray):
    # Each ciphers has len of 128

    # If server sends incorrect username message, then the client must have sent a login request
    # with incorrect username and password
    plaintext = xorByteArray(ciphers, BYTES_MESSAGE_INCORRECT_USERNAME)

    if startWithBytes(plaintext, prefixes=BYTES_PREFIX_LOGIN):
      proxyPlaintext[index] = bytesToString(plaintext)
      serverPlaintext[index] = MESSAGE_INCORRECT_USERNAME
      continue

    # If server send password mismath, then the client must have sent a login request with
    # correct username but incorrect password
    plaintext = xorByteArray(ciphers, BYTES_MESSAGE_PASSWORD_MISMATCH)

    if startWithBytes(plaintext, prefixes=BYTES_PREFIX_LOGIN):
      proxyPlaintext[index] = bytesToString(plaintext)
      serverPlaintext[index] = MESSAGE_PASSWORD_MISMATCH
      continue

    # If server send welcome, then the client must have sent a correct login request. 
    # Get two characters every iteration
    partialProxyPlaintext = xorByteArray(ciphers[0:len(BYTES_PREFIX_WELCOME)], BYTES_PREFIX_WELCOME)

    if startWithBytes(partialProxyPlaintext, prefixes=BYTES_PREFIX_LOGIN):
      serverPlaintext[index], proxyPlaintext[index] = decryptIteratively(
          ciphers=ciphers,
          probableServerPlaintext=copy.deepcopy(BYTES_PREFIX_WELCOME),
          probablyProxyPlaintext=copy.deepcopy(BYTES_PREFIX_LOGIN),
          numSpace=1)
      continue

    # If server send reply message, then the client must have sent a message
    # Get six characters every iteration
    partialProxyPlaintext = xorByteArray(ciphers[0:len(BYTES_PREFIX_REPLY_MESSAGE)],
                                         BYTES_PREFIX_REPLY_MESSAGE)

    if startWithBytes(partialProxyPlaintext, prefixes=BYTES_PREFIX_MESSAGE):
      serverPlaintext[index], proxyPlaintext[index] = decryptIteratively(
          ciphers=ciphers,
          probableServerPlaintext=copy.deepcopy(BYTES_PREFIX_REPLY_MESSAGE),
          probablyProxyPlaintext=copy.deepcopy(BYTES_PREFIX_MESSAGE),
          numSpace=3)
      continue

  return proxyPlaintext, serverPlaintext


def decryptIteratively(ciphers, probableServerPlaintext, probablyProxyPlaintext, numSpace):
  partialProxyPlaintext = xorByteArray(ciphers[0:len(probableServerPlaintext)],
                                       probableServerPlaintext)

  partialServerPlaintext = probableServerPlaintext
  charactersPerIteration = len(probableServerPlaintext) - len(probablyProxyPlaintext)
  offset = len(probablyProxyPlaintext)
  index = 0
  currentSpace = 0

  # Reveal some characters in proxy plaintext every iteration
  while offset + (charactersPerIteration * index) + charactersPerIteration < LENGTH_OF_MESSAGE:
    characters = ["" for i in range(charactersPerIteration)]
    for j in range(charactersPerIteration):
      characters[j] = partialProxyPlaintext[offset + (charactersPerIteration * index) + j]

    for j in range(len(characters)):
      character = characters[j]
      if character == ord(' '):
        currentSpace += 1
        if currentSpace == numSpace:
          characters = characters[0:j]
          break

    # We reveal more characters in server plaintext, so we append it our current knowledge
    # about server plaintext
    partialServerPlaintext.extend(characters)

    # Since we have new information about server plaintext, we can reveal new information in
    # proxy plaintext
    partialProxyPlaintext = xorByteArray(ciphers[0:len(partialServerPlaintext)],
                                         partialServerPlaintext)

    if currentSpace == numSpace:
      break

    index += 1

  serverPlaintext = addSpacesTillMaxLength(bytesToString(partialServerPlaintext))
  proxyPlaintext = bytesToString(xorByteArray(ciphers,
                                              bytearray(serverPlaintext,
                                                        encoding='utf-8')))

  return serverPlaintext, proxyPlaintext


def xorByteArray(bytes1, bytes2):
  return [b1 ^ b2 for b1, b2 in zip(bytes1, bytes2)]


def bytesToString(bytes):
  return "".join(map(chr, bytes))


def startWithBytes(byteString, prefixes):
  for i in range(len(prefixes)):
    if byteString[i] != prefixes[i]:
      return False
  return True


def reshapeCipherTextArray(bytes, rowDimension, columnDimension):
  if (rowDimension * columnDimension != len(bytes)):
    return None
  return [[bytes[i * columnDimension + j] for j in range(columnDimension)]
          for i in range(rowDimension)]


def printBytesInHex(bytes):
  print(' '.join(format(x, 'x') for x in bytes))


def printBytesInBinary(bytes):
  print(' '.join(format(x, 'b') for x in bytes))


if __name__ == '__main__':
  proxyPlaintext, serverPlaintext = decryptRC4()

  print('Proxy Plaintext')
  for index, text in enumerate(proxyPlaintext):
    print(index, text)

  print('Server Plaintext')
  for index, text in enumerate(serverPlaintext):
    print(index, text)
