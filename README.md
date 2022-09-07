# File-Recovery-on-FAT32-File-System

## Compiling:

We will grade your submission on a CentOS 7.9 system. We will compile your program using gcc 4.8.5. You must provide a Makefile, and by running make, it should generate an executable file named nyufile in the current working directory. Note that you need to add the compiler option -l crypto.

## How to run it:

Run `make` to generate an executable file named `nyufile` in the current working directory. Then run `./nyufile`.

## Usage:

Here are several ways to invoke the **nyufile** program. Here is its usage:

```
$ ./nyufile
Usage: ./nyufile disk <options>
  -i                     Print the file system information.
  -l                     List the root directory.
  -r filename [-s sha1]  Recover a contiguous file.
  -R filename -s sha1    Recover a possibly non-contiguous file.
```

The first argument is the filename of the disk image. After that, the options can be one of the following:

```
-i
-l
-r filename
-r filename -s sha1
-R filename -s sha1
```

## Introduction:

- Constructed a FAT32 file system on Linux and developed the ambiguous file recovery requests detection.
- Implemented the contiguously allocated file recovery with SHA-1 hash.
- Implemented the non-contiguously allocated file recovery function using DFS algorithm.