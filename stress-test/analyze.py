from loguru import logger

# Set the log level to ERROR or higher
logger.remove()

import time
import sys
from androguard.misc import AnalyzeDex

start_time = time.time()

h, d, dx = AnalyzeDex(sys.argv[1])

# Function to display xrefs for a given method
def show_method_xrefs(method):
    method_analysis = dx.get_method(method)
    print(f"Method: {method_analysis.name}")
    print("Called by:")
    for ref_class, ref_method, _ in method_analysis.get_xref_from():
        print(f"  - {ref_class.name} -> {ref_method.name}")

    print("Calls to:")
    for ref_class, ref_method, _ in method_analysis.get_xref_to():
        print(f"  - {ref_class.name} -> {ref_method.name}")
    print()

# Function to display xrefs for a given field
def show_field_xrefs(field):
    file_analysis = dx.get_field_analysis(field)
    print(f"Field: {file_analysis.name}")
    print("Referenced by:")
    for ref_class, ref_method in file_analysis.get_xref_read():
        print(f"  - Read by: {ref_class.name} -> {ref_method.name}")
    for ref_class, ref_method in file_analysis.get_xref_write():
        print(f"  - Written by: {ref_class.name} -> {ref_method.name}")
    print()
'''
# Iterate over classes and their methods to show method xrefs
for cls in d.get_classes():
    print(f"Class: {cls.name}")
    for method in cls.get_methods():
        show_method_xrefs(method)

# Iterate over classes and their fields to show field xrefs
for cls in d.get_classes():
    print(f"Class: {cls.name}")
    for field in cls.get_fields():
        show_field_xrefs(field)
'''
end_time = time.time()
delta = end_time - start_time
print(f"Execution time: {int(delta // 3600):02}h:{int((delta % 3600) // 60):02}m:{int(delta % 60):02}s:{int((delta % 1) * 1000):03}ms")
