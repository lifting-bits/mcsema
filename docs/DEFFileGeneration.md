# DEF file generation script

## Motivation

When performing CFG recovery, if mcsema encounters an external function whose calling convention or argument count is unknown, it will fail. The workaround is to provide mcsema with this information externally via a defs file. With one or two external functions, this is a simple enough task, but with more it becomes tedious and error prone work.

## Use case

This DEF file generation script is intended to be used when header files that declare the external functions are available. For instance, if you're attempting to lift a binary that relies upon a shared library, the external calls to the library would result in errors. However, you should have (or be able to acquire) the header files for that library, which wll permit the generation of the needed defs file.

## Usage

`python tools/generate_def_file.py /path/to/header/file.h` will print the DEF content for that file.

To process an entire directory, run `python tools/generate_def_files.py /path/to/include/*.h`.

Output is printed to stdout, so especially when processing many files at once, piping the output through `sort | uniq` can shrink the results.

## Dependencies

* python
* git
* access to github (for the first invocation)

## Example usage

```
user@host:tools/ $ python generate_def_file.py /usr/include/strings.h 
bcmp 3 C N
bcopy 3 C N
bzero 2 C N
index 2 C N
rindex 2 C N
ffs 1 C N
strcasecmp 2 C N
strncasecmp 3 C N
strcasecmp_l 3 C N
strncasecmp_l 4 C N
```
