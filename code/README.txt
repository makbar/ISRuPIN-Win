/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is the source code for the instruction set randomization using PIN tool on Windows project.

Usage:
The included tools are (in the order of recommended use):
1. objcopy - Encrypt the PE file with user specified key
2. ida - Run the patch using IDA to generate a patch file
   (to decode the data -- usually jump tables -- in the TEXT segment)
   for the PE file.
3. apply_isr_patch - Apply the patch to the encrypted PE (not the unencrypted) file.
Now, you can replace the executable with the encrypted+patched PE file.
4. db - Add the key to the database along with the executable's path.
5. isrupin-win - Run the program using pintool.

Note:
You can skip step 2 (patch file generation) when re-encrypting the binary with
a different key. The patch file needs to be generated only if the binary changes.

Each tool's folder has a README that describes the steps to setup, compile and run
that tool. Just follow the workflow steps given above in the right order.
