# Headless export of a Ghidra project

`ExportProject.java` is a read-only GhidraScript (written for Ghidra 11.4.3). It dumps the
open program to two files in the output directory:

- `export.json`: project and program info, memory blocks, symbols, functions (entry, body
  ranges, calling convention, prototype, parameters with storage) and the data types they use.
  Blocks are sorted by start address, symbols by address, functions by entry, data types by
  path name. No timestamps, so equal projects give equal files.
- `export.bin`: the bytes of every initialized memory block, concatenated in address order. Each
  block in the JSON gives its `sidecar_offset`/`sidecar_length`; the JSON names the file and its sha256.

Addresses are `space:hexoffset` strings (`ram:02000d6c`). There is no universal ID: Ghidra generates a new one per
session for types it creates on the fly, so exporting it would make runs differ. `function_count` is the function
manager's count and includes external functions; the `functions` array holds the non-external
ones (`getFunctions(true)`).

## Run

    JAVA_HOME=<jdk 21> PATH=$JAVA_HOME/bin:$PATH \
    <ghidra>/support/analyzeHeadless <projdir> <project> -process <program> \
      -readOnly -noanalysis -scriptPath scripts/export -postScript ExportProject.java <outdir>

`<outdir>` defaults to the current directory. Do not commit the output.
Note `-readOnly` still rewrites timestamps of the project's index files.
