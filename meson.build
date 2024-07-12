project('IPSEC-', 'c',
  version : '0.1',
  default_options : ['warning_level=3'])

# Add your source files here
sources = [
  'decrypt.c',
  'encrypt.c',
  'head.h',
  'input_output_original.c',
  'main.c',
]

# Find OpenSSL dependency
openssl_dep = dependency('openssl', version : '>= 1.1.0')

# Find threads dependency
thread_dep = dependency('threads')

# Create an executable target and link against OpenSSL
executable('IPSEC-',
           sources,
           dependencies : [openssl_dep, thread_dep],
           install : true)
