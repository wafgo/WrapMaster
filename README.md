<p align="center">
<img src="./images/WrapMasterLogo.png" width="500" height="500">
</p>

# WrapMaster

WrapMaster is a dynamic function wrapping tool that offers capabilities akin to those available with gcc/GNU ld’s --wrap option (https://linux.die.net/man/1/ld).  

This tool stands out by enabling the wrapping of function calls to symbols defined within the same compilation unit — a feature not supported by the --wrap linker option. 


## Why use WrapMaster?
The GNU linker, along with other proprietary linkers, provides a --wrap option for developers looking to intercept function calls. This option allows you to replace any function call with your own implementation, which in turn can call the original function under the __real_ function prefix. Detailed information on this interception mechanism is available in the GNU Linker documentation (https://linux.die.net/man/1/ld).

The --wrap option does not allow interception of function calls within the same compilation unit. This limitation has been discussed and documented in various resources, such as https://github.com/hedayat/powerfake/issues/2 and https://stackoverflow.com/questions/13961774/gnu-gcc-ld-wrapping-a-call-to-symbol-with-caller-and-callee-defined-in-the-sam.

A Solution to the Limitation WrapMaster is designed to overcome the limitations of the --wrap option by mimicking its behavior and allowing interception of calls within the same compilation unit. It achieves this by modifying the relocatable object files through the awesome LIEF Python library, which is detailed at [**LIEF’s GitHub repository**](https://github.com/lief-project/LIEF].

## Usage

Here is an example how the tool can be utilized to wrap a function.
Most likely you do not want to use the tool as a standalone tool but somehow integrate it into your Buildprocess, which allow **WrapMaster.py** to modify all object files from which your project is composed.
This example shows how it can be integrated for a GNU Make based project. For the invocation of the tool is shown [**here**](#Makefile)

The example contains two source files **main.c** and **square.c** and a **Makefile**. 

The example wraps the function **square()** which is implemented in **square.c**. The main function calls the first time **sqare()** directly and a second time through a function pointer **fp**. 

As the function pointer **fs** (which points to **square()**) is placed inside the same compilation unit as **square()**, using the **--wrap=square** linker option will __not__ work as expecte. The direct call to **square()** will be redirected through the **__wrap_square()** whereas the call through the function pointer **fs** wil __not__ be redirected. Please give it a try to verify that this is really true. 

Utilizing **WrapMaster.py** as shown in the files will make it work and both calls will be redirected through the wrapper.

### main.c
``` c title="main.c"
#include <stdio.h>

extern int square(int x);
extern int __real_square(int x);
typedef int fsquare(int x);

extern fsquare *fs;

int __wrap_square(int x)
{
    printf("_wrap called\n");
    return __real_square(x);
}

int main(int argc, char *argv[])
{
    printf("1: %i\n", square(3));
    printf("2: %i\n", fs(4));
    return 0;
}
```

### square.c
``` c title="square.c"
extern int square(int x);
typedef int fsquare(int x);

fsquare *fs = square;

int square(int x)
{
    return x * x;
}
```

### Makefile
``` Makefile title="Makefile"
CC := clang
PYTHON := python
WRAP_MASTER_PATH := <WRAP_MASTER_BUILD_PATH>/WrapMaster/

all: main.elf

clean:
	rm -f *.o *.elf

%.o: %.c
	$(CC) -Og -c -o $@ $<
	$(PYTHON) $(WRAP_MASTER_PATH)WrapMaster.py -wsquare $@

main.elf: main.o square.o
	$(CC) -Og -o $@ $^

```
