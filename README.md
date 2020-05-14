# Critical Phase-Aware (CPA) Partitioning Approach 

CPA is LLC (Last Level Cache) partitioning approach that performs an efficient cache space distribution among executing applications. To assign partitions (ways) of the LLC, Intel CAT is used.
This policy  is included in a framework named **manager** which is able to launch the experiments. 

### Experimental Platform

CPA was developed in an Intel(R) Xeon(R) CPU E5-2620 v4 @ 2.10GHz with 8 SMT-2 cores and a 20-ways 20 MB LLC.
The system was running an Ubuntu 16.04 with Linux kernel version 4.11. 


### Installing

A step by step series of examples that tell you how to get a development env running

1. Download or link the Linux source files to the Linux folder 

```
manager$ ln -s FILE_PATH_LINUX_FILES Linux
```

2. Download/clone (and build if needed) all the necessary libraries, each into a new folder:
- Linux Perf tool in the Linux source files
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

## Running the tests

A **test** folder has been included that includes 3 folders (noPart, CA and CPA). [Critical-Aware (CA) Partitioning Policy](https://doi.org/10.1007/978-3-319-96983-1_43) is also included in the framework.

Each folder includes a file, **template.mako**, that indicates the policy to launch as well as other execution parameters such as the performance counters that are going to be monitored. 

A **workloads.yaml** file is also needed. This file specifies the workload mixes to launch. Each line represents a mix, and each application in the mix is separated by a coma. The file **manager/scripts/templates/applications.mako** specifies each of the applications that can be used. **IMPORTANT NOTE: The root of the applications needs to be modified to adapt to your file path.**

To launch a given experiment, execute the following command
```
manager/test/FOLDER# bash ~/manager/scripts/launch.bash ../workloads.yaml
```

By default, experiments are launched 3 times. In **scripts/launch.bash** you can find the possible parameters that can be speficied.


