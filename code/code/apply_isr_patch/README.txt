/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is the source code of the apply_isr_patch. It reads the patch file,
parses the input PE file, converts the virtual addresses in patch file
to raw offset within PE file, and then patches the corresponding bytes
in the output file.

Pre-requisites:
1. From binary: The compiled executable can be found here: apply_isr_patch\Debug\apply_isr_patch.exe

2. From source: The visual studio project with the source code is attached. It has been created
and compiled using Visual Studio 2008.

Usage:
apply_isr_patch.exe xor_encryption_key input_executable output_executable patch_file
