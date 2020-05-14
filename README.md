# Critical Phase-Aware (CPA) Partitioning Approach 

CPA is LLC (Last Level Cache) partitioning approach that performs an efficient cache space distribution among executing applications. To assign partitions (ways) of the LLC, Intel CAT is used.
This policy is included in a framework named **manager** which is able to launch the experiments. 

### Experimental Platform

CPA was developed in an Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz with 8 SMT-2 cores and a 20-ways 20 MB LLC.
The system was running an Ubuntu 16.04 with Linux kernel version 4.11. 


### Installing

A step by step series of examples that tell you how to get a development env running

1. Download or link the linux source files to the Linux folder 

```
manager$ ln -s FILE_PATH_LINUX_FILES Linux
```

2. Download/clone (and build if needed) all the necessary libraries into their corresponding folders:
- [libcpuid: a small C library for x86 CPU detection and feature extraction](https://github.com/anrieff/libcpuid)
- [FMT: a modern formatting library](https://github.com/fmtlib/fmt)
- [cxx-prettyprint: a C++ library that allows automagic pretty-printing](https://github.com/louisdx/cxx-prettyprint)
- [Intel(R) Resource Director Technology - version compatible with this framework](https://github.com/vtselfa/intel-cmt-cat)
- [Intel Performance Counter Monitor - version compatible with this framework](https://github.com/vtselfa/intel-pcm)
- [stacktrace: C++ library for storing and printing backtraces](https://github.com/boostorg/stacktrace)
- Boost: copy the contents of stacktrace/include/boost/ to boost folder
```
manager$ cp -r stacktrace/include/boost/* boost 
```

3. Build the framework containing CPA: 
  a) Buid ~/manager/libminiperf library
  b) Build CPA framework (manager).
```
manager$ cd libminiperf
manager/libminiperf$ make
manager/libminiperf$ cd ..
manager$ make
```

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes. See deployment for notes on how to deploy the project on a live system.


## Running the tests

Explain how to run the automated tests for this system

### Break down into end to end tests

Explain what these tests test and why
