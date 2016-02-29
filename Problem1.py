from decryptRC4 import decryptRC4, PREFIX_WELCOME

_, proxyPlaintexts = decryptRC4()

usernames = []
for proxyPlaintext in proxyPlaintexts:

  # If the plaintext start with welcome prefix, this means that the user has login successfully
  if proxyPlaintext.startswith(PREFIX_WELCOME):
    usernames.append(proxyPlaintext.replace(PREFIX_WELCOME, '').replace(' ', ''))

with open('Problem1.txt', 'w') as file:
  [file.write(username + '\n') for username in usernames]
