import binascii

PREFIX_LOGIN = 'LOGIN '
PREFIX_MESSAGE = 'MESSAGE '
PREFIX_WELCOME = 'WELCOME '
PREFIX_REPLY_MESSAGE = 'REPLY MESSAGE '

LENGTH_OF_MESSAGE = 128


def addSpacesTillMaxLength(message):
  return message + ' ' * (LENGTH_OF_MESSAGE - len(message))


MESSAGE_INCORRECT_USERNAME = addSpacesTillMaxLength('INCORRECT USERNAME')
MESSAGE_PASSWORD_MISMATCH = addSpacesTillMaxLength('PASSWORD MISMATCH')

BYTES_PREFIX_LOGIN = bytearray(PREFIX_LOGIN)
BYTES_PREFIX_MESSAGE = bytearray(PREFIX_MESSAGE)
BYTES_PREFIX_WELCOME = bytearray(PREFIX_WELCOME)
BYTES_PREFIX_REPLY_MESSAGE = bytearray(PREFIX_REPLY_MESSAGE)
BYTES_MESSAGE_INCORRECT_USERNAME = bytearray(MESSAGE_INCORRECT_USERNAME)
BYTES_MESSAGE_PASSWORD_MISMATCH = bytearray(MESSAGE_PASSWORD_MISMATCH)


def main():
  proxyEncryptedMessage = None
  serverEncryptedMessage = None

  with open('ClientLogEnc.dat') as f:
    proxyEncryptedMessage = f.read()
    proxyEncryptedMessage = bytearray(proxyEncryptedMessage)

  with open('ServerLogEnc.dat') as f:
    serverEncryptedMessage = f.read()
    serverEncryptedMessage = bytearray(serverEncryptedMessage)

  ciphertextXORarray = [
      proxyByte ^ serverByte
      for proxyByte, serverByte in zip(proxyEncryptedMessage, serverEncryptedMessage)
  ]

  ciphertextXORarray = reshapeCipherTextArray(ciphertextXORarray, len(ciphertextXORarray) /
                                              LENGTH_OF_MESSAGE, LENGTH_OF_MESSAGE)

  # len of proxyPlaintext adn serverPlaintext is len(ciphertextXORarray) / LENGTH_OF_MESSAGE
  proxyPlaintext = ["" for i in range(len(ciphertextXORarray))]
  serverPlaintext = ["" for i in range(len(ciphertextXORarray))]

  for index, ciphers in enumerate(ciphertextXORarray):
    # Each ciphers has len of 128

    # If server sends incorrect username message, then the client must have sent a login request
    # with incorrect username and password
    plaintext = [cipher ^ message
                  for cipher, message in zip(ciphers, BYTES_MESSAGE_INCORRECT_USERNAME)]

    if startWithBytes(plaintext, BYTES_PREFIX_LOGIN):
      proxyPlaintext[index] = bytesToString(plaintext)
      serverPlaintext[index] = MESSAGE_INCORRECT_USERNAME
      continue

    # If server send password mismath, then the client must have sent a login request with
    # correct username but incorrect password
    plaintext = [cipher ^ message
                  for cipher, message in zip(ciphers, BYTES_MESSAGE_PASSWORD_MISMATCH)]

    if startWithBytes(plaintext, BYTES_PREFIX_LOGIN):
      proxyPlaintext[index] = bytesToString(plaintext)
      serverPlaintext[index] = MESSAGE_PASSWORD_MISMATCH
      continue

  print 'Proxy Plaintext'
  for t in proxyPlaintext:
    print t

  print 'Server Plaintext'
  for t in serverPlaintext:
    print t


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
  print ' '.join(format(x, 'x') for x in bytes)


def printBytesInBinary(bytes):
  print ' '.join(format(x, 'b') for x in bytes)


if __name__ == '__main__':
  main()
