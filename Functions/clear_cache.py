"""
- File to clear CSV files used for caching device and performance data
- Provides a "Are you sure?" prompt before deletion
"""

import os

def clear_saved_devices(filename='CSV/saved_devices.csv'):
    """Clear the saved devices CSV file after user confirmation."""
    if os.path.exists(filename):
        confirm = input(f"Are you sure you want to delete '{filename}'? (y/n): ")
        if confirm.lower() == 'y':
            os.remove(filename)
            print(f"Deleted '{filename}'.")
        else:
            print("Operation cancelled.")
    else:
        print(f"No saved devices file found at '{filename}'.")

def clear_performance_log(filename='CSV/performance_log.csv'):
    """Clear the performance log CSV file after user confirmation."""
    if os.path.exists(filename):
        confirm = input(f"Are you sure you want to delete '{filename}'? (y/n): ")
        if confirm.lower() == 'y':
            os.remove(filename)
            print(f"Deleted '{filename}'.")
        else:
            print("Operation cancelled.")
    else:
        print(f"No performance log file found at '{filename}'.")