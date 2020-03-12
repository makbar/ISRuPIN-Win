/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is the modified version of objcopy. The original source file,
the modified source file, the diff patch, and the binary executable are included.

Pre-requisites:
1. From binary: To run the included binary executable, you just need to
install cygwin, and run this executable from cygwin's bash terminal.

2. From source: To recompile objcopy, you will need to get cygwin, install gcc and make.
Then, get the binutils-2.21.1 source code, replace/patch the objcopy.c file
and compile it.

Usage:
./objcopy --encrypt-xor-key 0xDEAD input.exe encrypted-output.exe
