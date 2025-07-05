#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>  // Additional header in v2

// Version 2 of the program - updated version

void print_header() {
    printf("=================================\n");
    printf("      File Processing Tool v2.0  \n");  // Version number changed
    printf("=================================\n");
}

int process_data(int value) {
    // Version 2 implementation - different algorithm
    return value * 3;  // Multiplies by 3 instead of 2
}

void analyze_result(int result) {
    if (result > 100) {
        printf("Result is large: %d\n", result);
    } else {
        printf("Result is small: %d\n", result);
    }
    
    // Additional analysis in v2
    if (result % 2 == 0) {
        printf("Result is even\n");
    } else {
        printf("Result is odd\n");
    }
}

void cleanup_resources() {
    printf("Cleaning up resources...\n");
    printf("Performing additional cleanup steps...\n");  // Additional cleanup in v2
}

// New function in v2
void log_operation(const char* operation) {
    time_t now = time(NULL);
    printf("[%s] %s\n", ctime(&now), operation);
}

int main(int argc, char* argv[]) {
    print_header();
    
    printf("Starting file processing tool v2.0\n");  // Version number changed
    
    log_operation("Initialization");  // New function call
    
    int input_value = 42;
    if (argc > 1) {
        input_value = atoi(argv[1]);
    }
    
    printf("Processing value: %d\n", input_value);
    
    log_operation("Processing");  // New function call
    
    int result = process_data(input_value);
    
    printf("Processing complete. Result: %d\n", result);
    
    analyze_result(result);
    log_operation("Cleanup");  // New function call
    cleanup_resources();
    
    return 0;
} 