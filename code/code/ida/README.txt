/**
 * Muhammad Ali Akbar
 * maa2206@columbia.edu
 * Columbia University, NY
 *
 * For queries: ali.akbar.ceme@gmail.com
 *
 */

About:
This is a python script that uses IDA to generate patch file specifying
the jumptables (DATA in the .text section).

Pre-requisites:
IDA Pro (Tested on v6).

Usage:
Open the original (non-encrypted) PE file with IDA. Wait till initial
auto-analysis finishes. Run the python script from IDA (File->script file).
In the output window, click on each result and verify that there is no
false positive. If there is a false positive, you can fix it by telling
IDA to convert it to code and then function. Run the script again, a
patch file would have been generated (isr.func.patch).