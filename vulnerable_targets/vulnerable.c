/**
 * ABHIMANYU X CORE - Vulnerable C Target
 * For fuzzing and vulnerability testing
 * 
 * Compile with sanitizers:
 * gcc -g -fsanitize=address,undefined -o vulnerable vulnerable.c
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// VULNERABILITY 1: Buffer Overflow
void vulnerable_copy(char *input) {
    char buffer[64];
    // CRITICAL: No bounds checking
    strcpy(buffer, input);
    printf("Copied: %s\n", buffer);
}

// VULNERABILITY 2: Format String
void vulnerable_printf(char *user_input) {
    // CRITICAL: Format string vulnerability
    printf(user_input);
}

// VULNERABILITY 3: Integer Overflow
int vulnerable_calc(int a, int b) {
    // HIGH: Integer overflow not checked
    return a * b;
}

// VULNERABILITY 4: Use-After-Free
void vulnerable_uaf() {
    char *ptr = malloc(64);
    strcpy(ptr, "Hello");
    free(ptr);
    // CRITICAL: Use after free
    printf("%s\n", ptr);
}

// VULNERABILITY 5: Null Pointer Dereference
void vulnerable_null(char *input) {
    char *ptr = NULL;
    if (input[0] == 'a') {
        ptr = malloc(64);
    }
    // HIGH: Potential null dereference
    strcpy(ptr, input);
}

// VULNERABILITY 6: Command Injection via system()
void vulnerable_system(char *cmd) {
    // CRITICAL: Command injection
    system(cmd);
}

// VULNERABILITY 7: Stack-based Buffer Overflow
void vulnerable_stack(char *input) {
    char buffer[32];
    // CRITICAL: Stack overflow
    sprintf(buffer, "Data: %s", input);
    printf("%s\n", buffer);
}

// VULNERABILITY 8: Memory Leak
void vulnerable_leak() {
    char *ptr = malloc(256);
    strcpy(ptr, "Leaked memory");
    // HIGH: Memory leak - no free()
}

// VULNERABILITY 9: Race Condition
int shared_counter = 0;
void vulnerable_thread() {
    // MEDIUM: Race condition on shared variable
    shared_counter++;
}

// VULNERABILITY 10: Path Traversal via fopen
void vulnerable_file(char *filename) {
    char path[128];
    sprintf(path, "/data/%s", filename);
    // HIGH: Path traversal
    FILE *f = fopen(path, "r");
    if (f) {
        char buffer[256];
        fgets(buffer, 256, f);
        printf("Content: %s\n", buffer);
        fclose(f);
    }
}

// Main - test the vulnerable functions
int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("Testing vulnerable functions...\n");
    
    // Test each vulnerability
    vulnerable_copy(argv[1]);
    vulnerable_printf(argv[1]);
    vulnerable_system(argv[1]);
    vulnerable_stack(argv[1]);
    vulnerable_file(argv[1]);
    
    int result = vulnerable_calc(1000000, 1000000);
    printf("Calc result: %d\n", result);
    
    vulnerable_uaf();
    vulnerable_leak();
    vulnerable_null(argv[1]);
    
    return 0;
}
