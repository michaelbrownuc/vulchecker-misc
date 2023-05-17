# CFGAVE
Tool to extract Control Flow Graph Attribute Vectors using BinaryNinja API

## Dependencies

This project relies on the following packages:

 1. Networkx
 2. PyYAML
 3. BinaryNinja Commercial (personal edition does not support GUI-less processing)

## Usage
In root directory of repo:

`python3 src/cfgave.py path/to/input/binary`

or

`python3 src/cfgave.py path/to/input/directory/of/binaries/ --memory_cap [number of binaries to process]`

## Output
For each target binary CFGAVE will create a folder in the `./output/` directory with the name of the input binary. Inside that folder CFGAVE will create one output YAML file per function found in the binary. Each output file contains a readable Networkx graph in which each node represents a basic block in the function and its associated attibutes. Each edge in the graph is a control-flow edge in the source function.

### Memory Cap
When using CFGAVE to process large numbers of binaries in bulk, CFGAVE tends to accumulate memory over time. This is largely due to poor garbage collection on the part of Binary Ninja's API. CFGAVE has a configurable memory cap that can be used set the maximum number of binaries to analyze per round in order to avoid exhausting memory, which will result in the process being killed by the OS.

The default memory cap is 2000 binaries. If CFGAVE reaches the limit during bulk processing, it will quit. To process the remaining binaries, all the user must do is invoke the command again. CFGAVE will automatically skip binaries it has already produced output for. This can be done over and over to eventually process a large collection of binaries with minimal human interaction.

## Recovery
Code to programmatically recover and iterate through a function's graph is provided in `src/recovery.py`. To invoke recovery code, use the following command:

`python3 src/recovery.py path/to/output/file`




