/*
   Simple test harness for AFL++'s unicornafl c mode.

   This loads the simple_target.bin binary (precompiled as MIPS code) into
   Unicorn's memory map for emulation, places the specified input into
   simple_target's buffer (hardcoded to be at 0x300000), and executes 'main()'.
   If any crashes occur during emulation, this script throws a matching signal
   to tell AFL that a crash occurred.

   Run under AFL as follows:

   $ cd <afl_path>/unicorn_mode/samples/simple/
   $ make
   $ ../../../afl-fuzz -U -m none -i ./sample_inputs -o ./output -- harness @@ 
*/

// This is not your everyday Unicorn.
#define UNICORN_AFL

#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>

#include <unicorn/unicorn.h>

// Path to the file containing the binary to emulate
#define BINARY_FILE ("simple_target.bin")

// Memory map for the code to be tested
// Arbitrary address where code to test will be loaded
#define CODE_ADDRESS  (0x00100000) 
// Max size for the code (64kb)
#define STACK_ADDRESS (0x00200000)  
// Size of the stack (arbitrarily chosen)
#define STACK_SIZE	  (0x00010000)  
// Address where mutated data will be placed
#define DATA_ADDRESS  (0x00300000)  
// Maximum allowable size of mutated data
#define DATA_SIZE_MAX (0x00010000)  

static void hook_block(uc_engine *uc, uint64_t address, uint32_t size, void *user_data) {
    printf(">>> Tracing basic block at 0x%"PRIx64 ", block size = 0x%x\n", address, size);
}

static void hook_code(uc_engine *uc, uint64_t address, uint32_t size, void *user_data)
{
    printf(">>> Tracing instruction at 0x%"PRIx64 ", instruction size = 0x%x\n", address, size);
}

/* returns the filesize in bytes, -1 or error. */
static size_t afl_mmap_file(char *filename, char **buf_ptr) {

    int ret = -1;

    int fd = open(filename, O_RDONLY);

    struct stat st = {0};
    if (fstat(fd, &st)) goto exit;

    off_t in_len = st.st_size;

    *buf_ptr = mmap(0, in_len, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);

    if (*buf_ptr != MAP_FAILED) ret = in_len;

exit:
    close(fd);
    return ret;

}

/* Place the input at the right spot inside unicorn */
bool place_input_callback(
    uc_engine *uc, 
    char *input, 
    size_t input_len, 
    uint32_t persistent_round, 
    void *data
){
    // printf("Placing input with len %ld to %x\n", input_len, DATA_ADDRESS);
    if (input_len > DATA_SIZE_MAX) {
        // Test input too long, ignore this testcase
        return false;
    }
    uc_mem_write(uc, DATA_ADDRESS, input, input_len);
    return true;
}

void mem_map_checked(uc_engine *uc, uint64_t addr, size_t size, uint32_t mode) {
    // align to 0x1000
    if (size % 0x1000 != 0) {
        size = (size / 0x1000) + 1 * 0x1000;
    }
    uc_err err = uc_mem_map(uc, addr, size, mode);
    if (err != UC_ERR_OK) {
        printf("Error mapping %ld bytes at 0x%lx: %s (mode: %d)\n", size, addr, uc_strerror(err), mode);
        exit(1);
    }
}

int main(int argc, char **argv, char **envp) {
    if (argc == 1) {
        printf("Test harness for simple_target.bin. Usage: harness [-t] <inputfile>");
        exit(1);
    }
    bool tracing = false;
    char *filename = argv[1];
    if (argc > 2 && !strcmp(argv[1], "-t")) {
        tracing = true;
        filename = argv[2];
    }

    uc_engine *uc;
    uc_err err;
    uc_hook hooks[2];
    char *file_contents;

    // Initialize emulator in MIPS mode
    err = uc_open(UC_ARCH_MIPS, UC_MODE_MIPS32 + UC_MODE_BIG_ENDIAN, &uc);
    if (err) {
        printf("Failed on uc_open() with error returned: %u (%s)\n",
                err, uc_strerror(err));
        return -1;
    }

    printf("Loading data input from %s\n", BINARY_FILE);
    size_t len = afl_mmap_file(BINARY_FILE, &file_contents);
    if (len < 0) {
        perror("Could not read data from file.");
        return -2;
    }

    // Map memory.
    mem_map_checked(uc, CODE_ADDRESS, len, UC_PROT_ALL);

    // write machine code to be emulated to memory
    if (uc_mem_write(uc, CODE_ADDRESS, &file_contents, len) != UC_ERR_OK) {
        printf("Error writing to CODE");
    }

    // Release copied contents
    munmap(file_contents, len);

    // Set the program counter to the start of the code
    uint64_t start_address = CODE_ADDRESS;      // address of entry point of main()
    uint64_t end_address = CODE_ADDRESS + 0xf4; // Address of last instruction in main()
    uc_reg_write(uc, UC_MIPS_REG_PC, &start_address); // address of entry point of main()
    
    // Setup the Stack
    mem_map_checked(uc, STACK_ADDRESS, STACK_SIZE, UC_PROT_ALL);
    uint64_t stack_val = STACK_ADDRESS + STACK_SIZE;
    printf("%ld", stack_val);
    uc_reg_write(uc, UC_MIPS_REG_SP, &stack_val);

    // reserve some space for dat
    mem_map_checked(uc, DATA_ADDRESS, DATA_SIZE_MAX, UC_PROT_ALL);

    // If we want tracing output, set the callbacks here
    if (tracing) {
        // tracing all basic blocks with customized callback
        uc_hook_add(uc, &hooks[0], UC_HOOK_BLOCK, hook_block, NULL, 1, 0);
        uc_hook_add(uc, &hooks[1], UC_HOOK_CODE, hook_code, NULL, CODE_ADDRESS, CODE_ADDRESS + len - 1);
    }

    printf("Starting to fuzz :)\n");
    fflush(stdout);

    // let's gooo
    uc_afl_ret afl_ret = uc_afl_fuzz(
        uc,
        filename,
        place_input_callback,
        &end_address,
        1,
        NULL,
        false,
        1,
        NULL
    );
    switch(afl_ret) {
        case UC_AFL_RET_ERROR:
            printf("Error starting to fuzz");
            return -3;
            break;
        case UC_AFL_RET_NO_AFL:
            printf("No AFL attached - We are done with a single run.");
            break;
        default:
            break;
    } 
    return 0;
}
