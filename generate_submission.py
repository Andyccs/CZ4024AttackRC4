from shutil import copyfile
import os


def create_directory(dir_name):
  try:
    os.makedirs(dir_name)
  except OSError:
    if not os.path.isdir(dir_name):
      raise


def read_compile(lines, file):
  with open(file) as problem1_file:
    append_lines = [line for line in problem1_file]
    append_lines = append_lines[2:]

  # Generate submission file for Problem1.py
  with open('submission/%s' % file, 'w') as combined_file:
    [combined_file.write(line) for line in lines]
    [combined_file.write(append_line) for append_line in append_lines]


if __name__ == '__main__':
  create_directory('submission')

  # Combine decryptRC4 with Problem1 and Problem2
  with open('decryptRC4.py') as main_file:
    lines = [line for line in main_file]

    # remove lines after ""if __name__ == '__main__':""
    lines = lines[:177]

    read_compile(lines, 'Problem1.py')
    read_compile(lines, 'Problem2.py')

  # Copy the generated results
  copyfile("Problem1.txt", "submission/Problem1.txt")
  copyfile("Problem2.txt", "submission/Problem2.txt")
