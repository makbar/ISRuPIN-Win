#---------------------------------------------------------------------
# peparse - Parsing pe and finding data references within code to code
#
# Muhammad Ali Akbar <maa2206@columbia.edu>
#---------------------------------------------------------------------

import idautils
import idaapi
import idc
import types
import os

seg = FirstSeg()

while SegName(seg) != ".text" and seg != BADADDR:
	seg = NextSeg(seg)
	continue

start = SegStart(seg)
end = SegEnd(seg)

print SegName(seg) + ": [ " + hex(start) + " - " + hex(end) + " ]"

is_data = 0;
output_string = ""

for ea in range(start, end):
	drefs = list(DataRefsTo(ea));
	crefs_nonflow = list(CodeRefsTo(ea, 0));
	crefs_flow = list(CodeRefsTo(ea, 1));
	crefs = crefs_nonflow + crefs_flow;
	func_begin = GetFunctionAttr(ea, FUNCATTR_START);
	internal_ref = 0;
	for ref in drefs:
		if SegName(ref) == ".text":
			internal_ref = 1;
			break
	if not is_data and len(drefs) and internal_ref:
		if not len(crefs) and ea != func_begin:
			is_data = 1;
			print hex(start) + " " + hex(ea) + " " ,
			output_string += str(start) + " " + str(ea-start) + " "
	if is_data and len(crefs):
		is_data = 0;
		print hex(ea)
		output_string += str(ea-start) + "\n"

f = open("isr.func.patch", "w")
f.write(output_string)
f.close()

