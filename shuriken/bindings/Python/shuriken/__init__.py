import ctypes
import ctypes.util
import os
import sys
from os.path import join, exists

# Shuriken C interface

if sys.platform == "darwin":
    raise Exception("Not supported platform (yet...)")
elif sys.platform in ("win32", "cygwin"):
    _lib = "libshuriken.dll"
    common_paths = [
        "C:\\Program Files\\Shuriken",
        "C:\\Program Files (x86)\\Shuriken",
        os.getenv("PROGRAMFILES", "C:\\Program Files"),
        os.getenv("PROGRAMFILES(X86)", "C:\\Program Files (x86)")
    ]
else:
    _lib = "libshuriken.so"
    common_paths = [
        "/usr/local/lib",
        "/usr/lib",
        "/lib",
        "/usr/local/lib/shuriken",
        "/usr/lib/shuriken",
        "/lib/shuriken"
    ]


def _load_lib(path):
    lib_file = join(path, _lib)
    if exists(lib_file):
        return ctypes.cdll.LoadLibrary(lib_file)
    return None


_shuriken = None

# Attempt to load library from SHURIKEN_PATH environment variable if set
_path_list = [os.getenv("SHURIKEN_PATH", None)]
# Append common system paths
_path_list.extend(common_paths)

for _path in _path_list:
    if _path is None:
        continue
    _shuriken = _load_lib(_path)
    if _shuriken is not None:
        print(f"Library loaded from: {_path}")
        break
else:
    raise ImportError("ERROR: fail to load the dynamic library")

# import dex structures
from shuriken.dex import *


class Dex(object):
    """
    Object that will load a dex from a provided path.
    All the returned structures belong to `dex.py`
    """

    def __init__(self, dex_path: str = None):
        if dex_path is None:
            raise Exception("Error, you must provide a path to a dex file")

        # context object, this is not planned to
        # be exported to the user
        self.dex_context_object = None
        # cache of classes by the name of the class
        self.class_by_names = dict()
        # cache of classes by the id
        self.class_by_id = dict()
        # cache of the method by the dalvik name of the method
        self.method_by_name = dict()
        # cache of the disassembled method
        self.disassembled_methods = dict()
        # cache of the class analysis
        self.class_analysis_by_name = dict()
        # cache of the method analysis
        self.method_analysis_by_name = dict()

        _shuriken.parse_dex.restype = ctypes.c_void_p
        _shuriken.parse_dex.argtypes = [ctypes.c_char_p]

        self.dex_context_object = _shuriken.parse_dex(
            ctypes.c_char_p(dex_path.encode("utf-8"))
        )

    def __del__(self):
        _shuriken.destroy_dex.argtypes = [ctypes.c_void_p]
        _shuriken.destroy_dex(self.dex_context_object)

    def get_number_of_strings(self) -> ctypes.c_size_t:
        """
        :return: Number of strings available in the DEX file
        """
        _shuriken.get_number_of_strings.restype = ctypes.c_size_t
        _shuriken.get_number_of_strings.argtypes = [ctypes.c_void_p]
        return _shuriken.get_number_of_strings(self.dex_context_object)

    def get_string_by_id(self, id: ctypes.c_size_t) -> ctypes.c_char_p:
        """
        :param id: id of the string to retrieve
        :return: string from the provided id
        """
        _shuriken.get_string_by_id.argtypes = [ctypes.c_void_p, ctypes.c_size_t]
        _shuriken.get_string_by_id.restype = ctypes.c_char_p
        return _shuriken.get_string_by_id(self.dex_context_object, id)

    def get_number_of_classes(self) -> ctypes.c_uint16:
        """
        :return: Number of classes available in the DEX file
        """
        _shuriken.get_number_of_classes.argtypes = [ctypes.c_void_p]
        _shuriken.get_number_of_classes.restype = ctypes.c_uint16
        return _shuriken.get_number_of_classes(self.dex_context_object)

    def get_class_by_id(self, id: ctypes.c_uint16) -> hdvmclass_t | None:
        """
        :param id: id of the class to retrieve
        :return: :class:`hdvmclass_t` structure
        """
        if id in self.class_by_id.keys():
            return self.class_by_id[id]

        _shuriken.get_class_by_id.argtypes = [ctypes.c_void_p, ctypes.c_uint16]
        _shuriken.get_class_by_id.restype = ctypes.POINTER(hdvmclass_t)
        ptr = ctypes.cast(
            _shuriken.get_class_by_id(self.dex_context_object, id),
            ctypes.POINTER(hdvmclass_t),
        )

        if not ptr:
            return None

        self.class_by_id[id] = ptr.contents
        self.class_by_names[str(self.class_by_id[id].class_name)] = self.class_by_id[id]
        return self.class_by_id[id]

    def get_class_by_name(self, name: str) -> hdvmclass_t | None:
        """
        :param name: name of the class to retrieve
        :return: :class:`hdvmclass_t` structure
        """
        if name in self.class_by_names.keys():
            return self.class_by_names[name]
        _shuriken.get_class_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _shuriken.get_class_by_name.restype = ctypes.POINTER(hdvmclass_t)
        ptr = ctypes.cast(
            _shuriken.get_class_by_name(
                self.dex_context_object, ctypes.c_char_p(name.encode("utf-8"))
            ),
            ctypes.POINTER(hdvmclass_t),
        )

        if not ptr:
            return None
        self.class_by_names[name] = ptr.contents
        return self.class_by_names[name]

    def get_method_by_name(self, method_name: str) -> hdvmmethod_t | None:
        """
        :param method_name: dalvik name from the method to retrieve
        (e.g. LclassName;->methodName(parameters)RetType)
        :return: :class:`hdvmmethod_t` structure
        """
        if method_name in self.method_by_name.keys():
            return self.method_by_name[method_name]
        _shuriken.get_method_by_name.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _shuriken.get_method_by_name.restype = ctypes.POINTER(hdvmmethod_t)
        ptr = ctypes.cast(
            _shuriken.get_method_by_name(
                self.dex_context_object, ctypes.c_char_p(method_name.encode("utf-8"))
            ),
            ctypes.POINTER(hdvmmethod_t),
        )
        if not ptr:
            return None
        self.method_by_name[method_name] = ptr.contents
        return self.method_by_name[method_name]

    def disassemble_dex(self):
        """
        Apply the disassembly to the DEX file methods
        """
        _shuriken.disassemble_dex.argtypes = [ctypes.c_void_p]
        _shuriken.disassemble_dex(self.dex_context_object)

    def get_disassembled_method(self, method_name: str) -> dvmdisassembled_method_t | None:
        """
        :param method_name: Method name to retrieve its disassembled object
        :return: disassembled method with disassembly information
        """
        if method_name in self.disassembled_methods.keys():
            return self.disassembled_methods[method_name]
        _shuriken.get_disassembled_method.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _shuriken.get_disassembled_method.restype = ctypes.POINTER(dvmdisassembled_method_t)
        ptr = ctypes.cast(
            _shuriken.get_disassembled_method(self.dex_context_object, ctypes.c_char_p(method_name.encode("utf-8"))),
            ctypes.POINTER(dvmdisassembled_method_t))

        if not ptr:
            return None
        self.disassembled_methods[method_name] = ptr.contents
        return self.disassembled_methods[method_name]

    def create_dex_analysis(self, create_xrefs):
        """
        Create a DEX analysis object inside of context, for obtaining the analysis
        user must also call `analyze_classes`.
        :param create_xrefs: Boolean flag to create xrefs or not
        """
        _shuriken.create_dex_analysis.argtypes = [ctypes.c_void_p, ctypes.c_char]
        _shuriken.create_dex_analysis(self.dex_context_object, create_xrefs)

    def analyze_classes(self):
        """
        Analyze the classes, add fields and methods into the classes, optionally
        create the xrefs.
        """
        _shuriken.analyze_classes.argtypes = [ctypes.c_void_p]
        _shuriken.analyze_classes(self.dex_context_object)

    def get_analyzed_class(self, class_name: str) -> hdvmclassanalysis_t | None:
        """
        :param class_name: Name of the class to retrieve its analysis
        :return: :class:`hdvmclassanalysis_t` structure
        """
        if class_name in self.class_analysis_by_name:
            return self.class_analysis_by_name[class_name]
        _shuriken.get_analyzed_class.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _shuriken.get_analyzed_class.restype = ctypes.POINTER(hdvmclassanalysis_t)
        ptr = ctypes.cast(
            _shuriken.get_analyzed_class(self.dex_context_object, ctypes.c_char_p(class_name.encode("utf-8"))),
            ctypes.POINTER(hdvmclassanalysis_t))
        if not ptr:
            return None
        self.class_analysis_by_name[class_name] = ptr.contents
        return self.class_analysis_by_name[class_name]

    def get_analyzed_class_by_hdvmclass(self, class_: ctypes.POINTER(hdvmclass_t)) -> hdvmclassanalysis_t | None:
        """
        :param class_: :class:`hdvmclass_t` structure to retrieve
        :return: :class:`hdvmclassanalysis_t` structure
        """
        class_name = class_.class_name.decode()
        if class_name in self.class_analysis_by_name:
            return self.class_analysis_by_name[class_name]
        _shuriken.get_analyzed_class_by_hdvmclass.argtypes = [ctypes.c_void_p, ctypes.POINTER(hdvmclass_t)]
        _shuriken.get_analyzed_class_by_hdvmclass.restype = ctypes.POINTER(hdvmclassanalysis_t)
        ptr = ctypes.cast(
            _shuriken.get_analyzed_class_by_hdvmclass(self.dex_context_object, class_),
            ctypes.POINTER(hdvmclassanalysis_t))
        if not ptr:
            return None
        self.class_analysis_by_name[class_name] = ptr.contents
        return self.class_analysis_by_name[class_name]

    def get_analyzed_method(self, method_name: str) -> hdvmmethodanalysis_t | None:
        """
        :param method_name: Method name to retrieve its analysis
        :return: :class:`hdvmmethodanalysis_t` structure
        """
        if method_name in self.method_analysis_by_name:
            return self.method_analysis_by_name[method_name]
        _shuriken.get_analyzed_method.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        _shuriken.get_analyzed_method.restype = ctypes.POINTER(hdvmmethodanalysis_t)
        ptr = ctypes.cast(
            _shuriken.get_analyzed_method(self.dex_context_object, ctypes.c_char_p(method_name.encode("utf-8"))),
            ctypes.POINTER(hdvmmethodanalysis_t))
        if not ptr:
            return None
        self.method_analysis_by_name[method_name] = ptr.contents
        return self.method_analysis_by_name[method_name]

    def get_analyzed_method_by_hdvmmethod(self, method: ctypes.POINTER(hdvmmethod_t)) -> hdvmmethodanalysis_t | None:
        """
        :param method: :class:`hdvmmethod_t` structure
        :return: :class:`hdvmmethodanalysis_t` structure
        """
        method_name = method.dalvik_name.decode()
        if method_name in self.method_analysis_by_name:
            return self.method_analysis_by_name[method_name]
        _shuriken.get_analyzed_method_by_hdvmmethod.argtypes = [ctypes.c_void_p, ctypes.POINTER(hdvmmethod_t)]
        _shuriken.get_analyzed_method_by_hdvmmethod.restype = ctypes.POINTER(hdvmmethodanalysis_t)
        ptr = ctypes.cast(_shuriken.get_analyzed_method_by_hdvmmethod(self.dex_context_object, method),
                          ctypes.POINTER(hdvmmethodanalysis_t))
        if not ptr:
            return None
        self.method_analysis_by_name[method_name] = ptr.contents
        return self.method_analysis_by_name[method_name]


class Apk(object):
    """
    Object that will load an APK from a provided path.
    All the returned structures belong to `dex.py`
    """

    def __init__(self, apk_path: str = None, create_xrefs: bool = False):
        if apk_path is None:
            raise Exception("Error, Apk path is required")
        # Context object, this is not planned to
        # be exported to the user
        self.apk_context_object = None
        # cache of the dex files
        self.dex_files = dict()
        # cache of classes by id
        self.class_by_id = dict()
        # cache of the disassembled method
        self.disassembled_methods = dict()
        # cache of the class analysis
        self.class_analysis_by_name = dict()
        # cache of the method analysis
        self.method_analysis_by_name = dict()

        _shuriken.parse_apk.restype = ctypes.c_void_p
        _shuriken.parse_apk.argtypes = [ctypes.c_char_p, ctypes.c_int]

        create_xrefs_int = 0
        if create_xrefs:
            create_xrefs_int = 1

        self.apk_context_object = _shuriken.parse_apk(
            ctypes.c_char_p(apk_path.encode("utf-8")),
            create_xrefs_int
        )

    def __del__(self):
        _shuriken.destroy_apk.argtypes = [ctypes.c_void_p]
        _shuriken.destroy_apk(self.apk_context_object)

    def get_number_of_dex_files(self) -> int:
        """
        :return: Number of DEX files inside of the APK
        """
        _shuriken.get_number_of_dex_files.restype = ctypes.c_int
        _shuriken.get_number_of_dex_files.argtypes = [ctypes.c_void_p]
        return _shuriken.get_number_of_dex_files(self.apk_context_object)

    def get_dex_file_by_index(self, idx: int) -> ctypes.c_char_p | None:
        """
        :param idx: Index of the DEX file
        :return: DEX file string
        """
        if idx in self.dex_files:
            return self.dex_files[idx]
        _shuriken.get_dex_file_by_index.restype = ctypes.c_char_p
        _shuriken.get_dex_file_by_index.argtypes = [ctypes.c_void_p, ctypes.c_int]
        dex_file = _shuriken.get_dex_file_by_index(self.apk_context_object, idx)
        if not dex_file:
            return None
        self.dex_files[idx] = dex_file
        return dex_file

    def get_number_of_classes_for_dex_file(self, dex_file: str) -> int:
        """
        :return: Number of classes inside the DEX file
        """
        _shuriken.get_number_of_classes_for_dex_file.restype = ctypes.c_int
        _shuriken.get_number_of_classes_for_dex_file.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        return _shuriken.get_number_of_classes_for_dex_file(
            self.apk_context_object,
            ctypes.c_char_p(dex_file.encode("utf-8"))
        )

    def get_hdvmclass_from_dex_by_index(self, dex_file: str, idx: ctypes.c_uint16) -> hdvmclass_t | None:
        """
        :param dex_file: DEX file from the APK
        :param idx: index of the DEX file
        :return: hdvmclass_t
        """
        if dex_file in self.class_by_id and idx in self.class_by_id[dex_file]:
            return self.class_by_id[dex_file][idx]
        _shuriken.get_hdvmclass_from_dex_by_index.restype = ctypes.POINTER(hdvmclass_t)
        _shuriken.get_hdvmclass_from_dex_by_index.argtypes = [
            ctypes.c_void_p,
            ctypes.c_char_p,
            ctypes.c_uint16
        ]
        # call the function
        ptr = ctypes.cast(
            _shuriken.get_hdvmclass_from_dex_by_index(
                self.apk_context_object,
                ctypes.c_char_p(dex_file.encode("utf-8")),
                idx
            ),
            ctypes.POINTER(hdvmclass_t),
        )
        # if no content...
        if not ptr:
            return None
        # add it to the cache
        if dex_file not in self.class_by_id:
            self.class_by_id[dex_file] = dict()
        self.class_by_id[dex_file][idx] = ptr.contents
        return self.class_by_id[dex_file][idx]

    def get_disassembled_method_from_apk(self, method_name: str) -> dvmdisassembled_method_t | None:
        """
        :param method_name: Method name to retrieve its disassembled object
        :return: disassembled method with disassembly information
        """
        if method_name in self.disassembled_methods:
            return self.disassembled_methods[method_name]
        _shuriken.get_disassembled_method_from_apk.restype = ctypes.POINTER(dvmdisassembled_method_t)
        _shuriken.get_disassembled_method_from_apk.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        ptr = ctypes.cast(
            _shuriken.get_disassembled_method(self.apk_context_object, ctypes.c_char_p(method_name.encode("utf-8"))),
            ctypes.POINTER(dvmdisassembled_method_t))

        if not ptr:
            return None
        self.disassembled_methods[method_name] = ptr.contents
        return self.disassembled_methods[method_name]

    def get_analyzed_class_from_apk(self, class_name: str) -> hdvmclassanalysis_t | None:
        """
        :param class_name: Name of the class to retrieve its analysis
        :return: :class:`hdvmclassanalysis_t` structure
        """
        if class_name in self.class_analysis_by_name:
            return self.class_analysis_by_name[class_name]
        _shuriken.get_analyzed_class_from_apk.restype = ctypes.POINTER(hdvmclassanalysis_t)
        _shuriken.get_analyzed_class_from_apk.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        ptr = ctypes.cast(
            _shuriken.get_analyzed_class(self.apk_context_object, ctypes.c_char_p(class_name.encode("utf-8"))),
            ctypes.POINTER(hdvmclassanalysis_t))
        if not ptr:
            return None
        self.class_analysis_by_name[class_name] = ptr.contents
        return self.class_analysis_by_name[class_name]

    def get_analyzed_class_by_hdvmclass_from_apk(self, class_: ctypes.POINTER(hdvmclass_t)) -> hdvmclassanalysis_t | None:
        """
        :param class_: :class:`hdvmclass_t` structure to retrieve
        :return: :class:`hdvmclassanalysis_t` structure
        """
        class_name = class_.class_name.decode()
        if class_name in self.class_analysis_by_name:
            return self.class_analysis_by_name[class_name]
        _shuriken.get_analyzed_class_by_hdvmclass_from_apk.restype = ctypes.POINTER(hdvmclassanalysis_t)
        _shuriken.get_analyzed_class_by_hdvmclass_from_apk.argtypes = [ctypes.c_void_p, ctypes.POINTER(hdvmclass_t)]
        ptr = ctypes.cast(
            _shuriken.get_analyzed_class_by_hdvmclass(
                self.apk_context_object,
                class_),
            ctypes.POINTER(hdvmclassanalysis_t))
        if not ptr:
            return None
        self.class_analysis_by_name[class_name] = ptr.contents
        return self.class_analysis_by_name[class_name]

    def get_analyzed_method_from_apk(self, method_full_name: str) -> hdvmmethodanalysis_t | None:
        """
        :param method_full_name: Method name to retrieve its analysis
        :return: :class:`hdvmmethodanalysis_t` structure
        """
        if method_full_name in self.method_analysis_by_name:
            return self.method_analysis_by_name[method_full_name]
        _shuriken.get_analyzed_method_from_apk.restype = ctypes.POINTER(hdvmmethodanalysis_t)
        _shuriken.get_analyzed_method_from_apk.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
        ptr = ctypes.cast(
            _shuriken.get_analyzed_method_from_apk(self.apk_context_object,
                                                   ctypes.c_char_p(method_full_name.encode("utf-8"))),
            ctypes.POINTER(hdvmmethodanalysis_t)
        )
        if not ptr:
            return None
        self.method_analysis_by_name[method_full_name] = ptr.contents
        return self.method_analysis_by_name[method_full_name]

    def get_analyzed_method_by_hdvmmethod_from_apk(self, method: ctypes.POINTER(hdvmmethod_t)) -> hdvmmethodanalysis_t | None:
        """
        :param method: :class:`hdvmmethod_t` structure
        :return: :class:`hdvmmethodanalysis_t` structure
        """
        method_name = method.dalvik_name
        if method_name in self.method_analysis_by_name:
            return self.method_analysis_by_name[method_name]
        _shuriken.get_analyzed_method_by_hdvmmethod_from_apk.argtypes = [ctypes.c_void_p, ctypes.POINTER(hdvmmethod_t)]
        _shuriken.get_analyzed_method_by_hdvmmethod_from_apk.restype = ctypes.POINTER(hdvmmethodanalysis_t)
        ptr = ctypes.cast(_shuriken.get_analyzed_method_by_hdvmmethod_from_apk(self.apk_context_object, method),
                          ctypes.POINTER(hdvmmethodanalysis_t))
        if not ptr:
            return None
        self.method_analysis_by_name[method_name] = ptr.contents
        return self.method_analysis_by_name[method_name]
