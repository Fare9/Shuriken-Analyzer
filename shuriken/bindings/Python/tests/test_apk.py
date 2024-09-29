#!/usr/bin/env python3
#-*- coding: utf-8 -*-

from shuriken import *

def print_hdvmclass_data(class_: hdvmclass_t):
    for i in range(class_.direct_methods_size):
        direct_method = class_.direct_methods[i]
        print(f"Direct Method {i}:")
        # Now `first_direct_method` holds the data of the first direct method
        # You can access its fields like:
        print("\tMethod Name:", direct_method.method_name)
        print("\tPrototype:", direct_method.prototype)
        print("\tAccess Flags:", direct_method.access_flags)
        print("\tCode Size:", direct_method.code_size)
        # Assuming code is a buffer of bytes, you can access its content like this
        # print("Code Content:", bytes(first_direct_method.code[:first_direct_method.code_size]))
        print("\tDalvik Name:", direct_method.dalvik_name)
        print("\tDemangled Name:", direct_method.demangled_name)

    for i in range(class_.virtual_methods_size):
        virtual_method = class_.virtual_methods[i]
        print(f"Virtual Method {i}:")
        # Now `first_direct_method` holds the data of the first direct method
        # You can access its fields like:
        print("\tMethod Name:", virtual_method.method_name)
        print("\tPrototype:", virtual_method.prototype)
        print("\tAccess Flags:", virtual_method.access_flags)
        print("\tCode Size:", virtual_method.code_size)
        # Assuming code is a buffer of bytes, you can access its content like this
        # print("Code Content:", bytes(first_direct_method.code[:first_direct_method.code_size]))
        print("\tDalvik Name:", virtual_method.dalvik_name)
        print("\tDemangled Name:", virtual_method.demangled_name)

    for i in range(class_.instance_fields_size):
        instance_field = class_.instance_fields[i]
        print(f"Instance Field {i}:")
        print("\tField Name:", instance_field.name)
        print("\tField Type:", instance_field.type)
        print("\tField Type Value:", instance_field.type_value)
        print("\tAccess Flags:", instance_field.access_flags)

    for i in range(class_.static_fields_size):
        static_field = class_.static_fields[i]
        print(f"Static Field {i}:")
        print("\tField Name:", static_field.name)
        print("\tField Type:", static_field.type)
        print("\tField Type Value:", static_field.type_value)
        print("\tAccess Flags:", static_field.access_flags)

def print_disassembly_data(apk: Apk, class_: hdvmclass_t):
    for i in range(class_.direct_methods_size):
        direct_method = class_.direct_methods[i]
        method_name = direct_method.dalvik_name.decode()
        disassembled_method = apk.get_disassembled_method_from_apk(method_name)
        disassembler_str = disassembled_method.method_string
        print(f"{disassembler_str.decode()}\n")
    for i in range(class_.virtual_methods_size):
        virtual_method = class_.virtual_methods[i]
        method_name = virtual_method.dalvik_name.decode()
        disassembled_method = apk.get_disassembled_method_from_apk(method_name)
        disassembler_str = disassembled_method.method_string
        print(f"{disassembler_str.decode()}\n")

if __name__ == '__main__':
    path = "../../../tests/compiled/"
    for file in os.listdir(path):

        if not file.endswith(".apk"):
            continue

        apk = Apk(
            os.path.join(path, file), True
        )

        print(f"Number of dex files: {apk.get_number_of_dex_files()}")

        for j in range(apk.get_number_of_dex_files()):
            dex_file = apk.get_dex_file_by_index(j)

            print(f"Dex file {j}: {dex_file}")

            print(f"Number of classes for the dex file: {apk.get_number_of_classes_for_dex_file(dex_file)}")

            for i in range(apk.get_number_of_classes_for_dex_file(dex_file)):
                class_: hdvmclass_t = apk.get_hdvmclass_from_dex_by_index(dex_file, i)
                print(f"Class name: {class_.class_name}")

                print_hdvmclass_data(class_)

                print_disassembly_data(apk, class_)

                class_name = class_.class_name.decode()

                class_analysis: hdvmclassanalysis_t = apk.get_analyzed_class_from_apk(class_name)

                print("Class Analysis Information")
                print(f"Class analyzed name: {class_analysis.name_.decode()}")
                print(f"Number of methods: {class_analysis.n_of_methods}")

                if class_analysis.extends_:
                    print(f"Extends a class: {class_analysis.extends_.decode()}")
                print(f"Is external?: ", end="")
                if class_analysis.is_external == 0:
                    print("False")
                else:
                    print("True")
                print("Method Analysis Information")
                for i in range(int(class_analysis.n_of_methods)):
                    method_analysis: hdvmmethodanalysis_t = class_analysis.methods[i].contents
                    print(f"Method name: {method_analysis.full_name.decode()}")
                    if method_analysis.method_string is not None:
                        print(f"{method_analysis.method_string.decode()}")
                print("Field Analysis Information")
                for i in range(int(class_analysis.n_of_fields)):
                    field_analysis: hdvmfieldanalysis_t = class_analysis.fields[i].contents
                    print(f"Field name: {field_analysis.name.decode()}")
