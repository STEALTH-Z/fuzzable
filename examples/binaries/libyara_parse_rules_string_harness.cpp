/* 
 * libyara_parse_rules_string_harness.cpp
 * 
 *      Automatically generated fuzzer harness for `parse_rules_string` in `libyara`. Make sure to add in implementation
 *      for any other necessary functionality to make this work.
 * 
 *      Make sure the target binary/shared object is in the same directory!
 *
 *      To build for AFL-QEMU, optimal for black-box and file-based fuzzing:
 *
 *          $ gcc libyara_parse_rules_string_harness.cpp -no-pie -o libyara_parse_rules_string_harness -ldl
 * 
 *          # check out more binary fuzzing strategies at https://aflplus.plus/docs/binaryonly_fuzzing/
 *          $ afl-fuzz -Q -m none -i <SEEDS> -o out/ -- ./libyara_parse_rules_string_harness
 *
 *      To build for libFuzzer, optimal for generative buffer fuzzing:
 *
 *          $ clang -DLIBFUZZER -g -fsanitize=fuzzer,address libyara_parse_rules_string_harness -no-pie -o libyara_parse_rules_string_harness -ldl
 *          $ ./libyara_parse_rules_string_harness
 *
 */

#include <dlfcn.h>
#include <alloca.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>
#include <sys/stat.h>

#define FUZZER_BUF 1024 * 1024
#define TARGET_NAME "parse_rules_string"

// TODO: Uncomment this if you want to pass files in as inputs to the target
//#define FILE_FUZZING 1

// TODO: Uncomment this if you want to switch on using libFuzzer instead
//#define LIBFUZZER 1

/* alias for function pointer to the target function */
typedef void* (*yr_create_context)();
typedef void* (*parse_rules_string)(uint8_t*, void*);

// TODO: Manually add any other aliases here, such as pointers responsible for freeing up resources

void* handle = NULL;

void CloseLibrary(void)
{{
    if (handle)
        dlclose(handle);
    handle = NULL;
}}


#ifdef LIBFUZZER
extern "C"
#endif
int LoadLibrary(void)
{{
    handle = dlopen("./libyara.so", RTLD_LAZY);
    atexit(CloseLibrary);
    return handle != NULL;
}}

static uint8_t fuzzBuffer[FUZZER_BUF];

#ifdef LIBFUZZER
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* Data, size_t Size)
#else
int main (int argc, char** argv)
#endif
{{
    if (!LoadLibrary()) {{
        printf("%s\n", dlerror());
        return -1;
    }}

    int read_fd = 0;

#ifndef LIBFUZZER
  #ifdef FILE_FUZZING
    if (argc != 2)
        return -1;

    const char* filepath = argv[1];
    read_fd = open(filepath, O_RDONLY);
    if (read_fd < 0)
        return -1;
  #endif

    ssize_t Size = read(read_fd, fuzzBuffer, FUZZER_BUF);
    if (Size < 0)
        return -1;
#endif

    parse_rules_string target = (parse_rules_string) dlsym(handle, TARGET_NAME);
    yr_create_context ctx_call = (yr_create_context) dlsym(handle, "yr_create_context");
    printf("%s=%p\n", TARGET_NAME, target);

    ////////////////////////////
    // FUZZER ENTRY HERE
    ////////////////////////////

    // Harness generation currently assumes that the only arguments
    // are a pointer to the buffer and the size. Make necessary modifications
    // here to ensure the function being called has the right arguments.
    void *ctx_res = ctx_call();
    void *res = target(fuzzBuffer, ctx_res);

    // Introduce other functionality, ie. freeing objects, checking return values.

    return 0;
}}
