# -*- coding: utf-8 -*-
"""
Created on Sat Feb 15 20:39:25 2024

@author: IAN CARTER KULANI

"""
import re

# Function to check for SQL injection patterns
def detect_sql_injection(sql_query):
    # Define a list of common SQL injection patterns
    patterns = [
        r"(--|\#|\/*.*\*\/)",  # SQL comments
        r"(\bSELECT\b|\bUNION\b|\bDROP\b|\bINSERT\b|\bUPDATE\b|\bDELETE\b)",  # SQL commands
        r"(\bOR\b\s+\d+=\d+|\bAND\b\s+\d+=\d+)",  # OR/AND based injections (e.g., OR 1=1)
        r"(\bOR\b\s+\'[^\']*\'\s*=\s*\'[^\']*\')",  # OR 'value' = 'value' injection
        r"(\b--\s*)",  # SQL comments at the end of a query
        r"(\')",  # Single quote which can be used for injection
        r"(;)",  # Semicolon used to terminate statements
    ]

    # Check for each pattern in the SQL query
    for pattern in patterns:
        if re.search(pattern, sql_query, re.IGNORECASE):
            return True  # Return True if a potential SQL injection is found

    return False  # No injection detected

# Main function to prompt user for input and check for SQL injection
def main():
    print("SQL Injection Detection Tool\n")
    sql_query = input("Please enter an SQL query:")

    if detect_sql_injection(sql_query):
        print("\nWarning: Potential SQL injection detected!")
    else:
        print("\nNo SQL injection detected. The query seems safe.")

# Run the tool
if __name__ == "__main__":
    main()
