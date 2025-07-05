#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Version 1 of the program - original version

void print_header() {
    printf("=================================\n");
    printf("      File Processing Tool v1.0  \n");
    printf("=================================\n");
}

int process_data(int value) {
    // Version 1 implementation
    return value * 2;
}

void analyze_result(int result) {
    if (result > 100) {
        printf("Result is large: %d\n", result);
    } else {
        printf("Result is small: %d\n", result);
    }
}

void cleanup_resources() {
    printf("Cleaning up resources...\n");
    // Basic cleanup in v1
}

int main(int argc, char* argv[]) {
    print_header();
    
    printf("Starting file processing tool v1.0\n");
    
    int input_value = 42;
    if (argc > 1) {
        input_value = atoi(argv[1]);
    }
    
    printf("Processing value: %d\n", input_value);
    
    int result = process_data(input_value);
    
    printf("Processing complete. Result: %d\n", result);
    
    analyze_result(result);
    cleanup_resources();
    
    return 0;
} 