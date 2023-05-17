# juliet-labeling

## Setup

Install [cppp](http://www.muppetlabs.com/~breadbox/software/cppp.html).

## Usage

`process_juliet.py --help`

## Examples
### Label Format
```
[
    {
        "filename": "file.c",
        "line_number": 34,
        "label": "root_cause"
    },
    {
        "filename": "file.c",
        "line_number": 36,
        "label": "manifestation"
    }
]
```

### CWE-121 Stack-Based Buffer Overflow
```
int data = atoi(inputBuffer);
int buffer[10] = { 0 }; // declared_buffer
buffer[data] = 1; // stack_overflow
```
### CWE-122 Heap-Based Buffer Overflow
```
// malloc allocates 10 bytes instead (sizeof(int) * 10) bytes
data = (int *)malloc(10); // declared_buffer
for (i = 0; i < 10; i++) {
    data[i] = source[i]; // heap_overflow
}

```
### CWE-190 Integer Overflow
```
char result = data + 1; // overflowed_variable
printHexCharLine(result); // overflowed_call
```
### CWE-191 Integer Underflow
```
char result = data * 2; // underflowed_variable
printHexCharLine(result); // underflowed_call
```
### CWE-415 Double Free
```
free(data); // first_free
free(data); // second_free
```
### CWE-416 Use After Free
```
free(data); // freed_variable
printLine(data); // use_after_free
```
Note: When a freed variable is passed to a function, ASAN identifies the UAF at the use site within the function. The label should be at the function call for consistency.
