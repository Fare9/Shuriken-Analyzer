//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_analysis.h
// @brief Classes used for the analysis of DEX files, specifically the analysis of DEX instructions
// for obtaining information like cross-references or for quickly accessing some information.

#ifndef SHURIKENPROJECT_DEX_ANALYSIS_H
#define SHURIKENPROJECT_DEX_ANALYSIS_H

#include "shuriken/analysis/Dex/external_class.h"
#include "shuriken/analysis/Dex/external_field.h"
#include "shuriken/analysis/Dex/external_method.h"
#include "shuriken/disassembler/Dex/disassembled_method.h"
#include "shuriken/parser/Dex/dex_encoded.h"
#include "shuriken/parser/Dex/parser.h"


#include <set>
#include <span>


namespace shuriken::analysis::dex {
    class ClassAnalysis;
    class MethodAnalysis;
    class FieldAnalysis;

    using class_method_idx_t = std::vector<std::tuple<ClassAnalysis *, MethodAnalysis *, std::uint64_t>>;
    using class_method_idx_iterator_t = class_method_idx_t::iterator;

    using class_field_idx_t = std::vector<std::tuple<ClassAnalysis *, FieldAnalysis *, std::uint64_t>>;
    using class_field_idx_iterator_t = class_field_idx_t::iterator;

    using class_idx_t = std::vector<std::pair<ClassAnalysis *, std::uint64_t>>;
    using class_idx_iterator_t = class_idx_t::iterator;

    using classxref_t = std::unordered_map<ClassAnalysis *,
                                           std::set<std::tuple<shuriken::dex::TYPES::ref_type,
                                                               MethodAnalysis *,
                                                               std::uint64_t>>>;
    using classxref_iterator_t = classxref_t::iterator;

    /// @brief Class to represent a basic block in a dalvik method, basic blocks contains
    /// instructions and some metadata about the block.
    class DVMBasicBlock {
    private:
        /// @brief Instructions of the current basic block
        std::span<disassembler::dex::Instruction *> instructions_;

        /// @brief does it contain the code from try
        bool try_block = false;
        /// @brief which are their catch blocks
        std::set<DVMBasicBlock *> catch_blocks;

        /// @brief does it contain the code from catch block
        bool catch_block = false;

        /// @brief some catch block at the end of the code will
        /// be empty
        bool is_empty_block = false;

        std::uint64_t first_address = 0;
        std::uint64_t last_address = 0;

        /// @brief type of contained handler
        parser::dex::DVMType *handler_types;

        /// @brief Name of the block composed by first and last address
        std::string name;

        /// @brief String that stores a whole block representation
        std::string block_string;

    public:
        using read_instructions_t = std::span<disassembler::dex::Instruction *>;
        using read_instructions_iterator_t = read_instructions_t::iterator;
        using read_instructions_reverse_iterator_t = read_instructions_t::reverse_iterator;

        /// @brief Return a range to go through the instructions in forward order
        /// @return iterator to instructions.
        iterator_range<read_instructions_iterator_t> instructions();

        /// @brief Return a range to go through the instructions in backward order
        /// @return reverse iterator to instructions
        iterator_range<read_instructions_reverse_iterator_t> reverse_instructions();

    public:
        DVMBasicBlock(read_instructions_t instructions_);

        DVMBasicBlock(std::uint64_t first_address, std::uint64_t last_address);

        /// avoid any kind of copy constructor
        DVMBasicBlock(const DVMBasicBlock &temp_obj) = delete;
        DVMBasicBlock &operator=(const DVMBasicBlock &temp_obj) = delete;

        /// @brief Obtain the number of instructions from the instructions vector
        /// @return number of instructions of DVMBasicBlock
        size_t get_nb_instructions() const;

        /// @brief Get a reference to the vector of instructions
        /// @return instructions from the block
        read_instructions_t get_instructions();

        /// @brief Return the last instruction in case this is a terminator instruction
        /// @return terminator instruction
        disassembler::dex::Instruction *get_terminator();

        /// @brief Get the first address of the basic block in case there are instructions
        /// @return first address of basic block
        std::uint64_t get_first_address() const;

        /// @brief Get the last address of the basic block in case there are instructions
        /// @return last address of basic block
        std::uint64_t get_last_address() const;

        /// @brief Get the name of the basic block based on its address.
        /// @return BB.<address>
        std::string_view get_name();

        /// @brief Is the current block a try-block?
        /// @return true in case this is a try block
        bool is_try_block() const;

        /// @brief Set the block is a try block
        /// @param try_block new value
        void set_try_block(bool try_block);

        /// @return Get the catch blocks belonging to
        /// the try block
        std::set<DVMBasicBlock *> &get_catch_blocks();

        /// @brief Add a catch block for the try block
        /// @param catch_block the block to include
        void add_catch_block(DVMBasicBlock *bb);

        /// @brief Is the current block a catch-block?
        /// @return true in case this is a catch block
        bool is_catch_block() const;

        /// @brief Set the block is a catch block
        /// @param catch_block new value
        void set_catch_block(bool catch_block);

        /// @brief Get the type of handler in case is a catch block
        /// @return handler type
        parser::dex::DVMType *get_handler_type();

        /// @brief Set a handler type
        /// @param handler handler type
        void set_handler_type(parser::dex::DVMType *handler);

        std::string_view toString();
    };

    /// @brief Class to keep all the Dalvik Basic Blocks from a method
    class BasicBlocks {
    public:
        /// @brief connection between blocks
        using connected_blocks_t = std::unordered_map<
                DVMBasicBlock *,
                std::set<DVMBasicBlock *>>;

        /// @brief edges between nodes
        using edges_t = std::vector<
                std::pair<DVMBasicBlock *, DVMBasicBlock *>>;

        /// @brief type of a node
        enum node_type_t {
            JOIN_NODE = 0,// len(predecessors) > 1
            BRANCH_NODE,  // len(successors) > 1
            REGULAR_NODE, // other cases
        };

        /// @brief Iterator for going through a list of basic blocks in order
        using nodesiterator_t = std::vector<DVMBasicBlock *>::iterator;
        /// @brief Iterator for going through a list of basic blocks in reverse order
        using reversenodesiterator_t = std::vector<DVMBasicBlock *>::reverse_iterator;

        /// @brief Iterator for going throw a list of successors or predecessors
        using nodesetiterator_t = std::set<DVMBasicBlock *>::iterator;
        /// @brief Iterator for going throw a list of successors or predecessors in reverse order
        using reversenodesetiterator_t = std::set<DVMBasicBlock *>::reverse_iterator;

        /// @brief Iterator for going through the edges
        using edgesiterator_t = edges_t::iterator;
        /// @brief Iterator for going through the edges in reverse order
        using reverseedgesiterator_t = edges_t::reverse_iterator;

    private:
        /// @brief all the basic blocks from a method
        std::vector<DVMBasicBlock *> nodes_;

        /// @brief set of nodes that are predecessors of a node
        connected_blocks_t predecessors_;

        /// @brief set of nodes that are successors of a node
        connected_blocks_t successors_;

        /// @brief edges in the graph, this is a directed graph
        edges_t edges_;

        /// @brief All the basic blocks from the method
        std::string basic_blocks_string;

    public:
        /// @return iterator to all the nodes
        iterator_range<nodesiterator_t> nodes();

        /// @return reverse iterator to all the nodes
        iterator_range<reversenodesiterator_t> reverse_nodes();

        /// @return iterator to the edges
        iterator_range<edgesiterator_t> edges();

        /// @return reverse iterator to the edges
        iterator_range<reverseedgesiterator_t> reverse_edges();

        /// @brief Check if successors exist for a node and return its successors
        /// @param node to get its successors
        /// @return successors from provided node
        iterator_range<nodesetiterator_t> successors(DVMBasicBlock *node);

        /// @brief Check if predecessors exist for a node and return its successors
        /// @param node to get its predecessors
        /// @return predecessors from provided node
        iterator_range<nodesetiterator_t> predecessors(DVMBasicBlock *node);

        iterator_range<reversenodesetiterator_t> reverse_successors(DVMBasicBlock *node);

        iterator_range<reversenodesetiterator_t> reverse_predecessors(DVMBasicBlock *node);

    public:
        BasicBlocks() = default;

        /// avoid any kind of copy constructor
        BasicBlocks(const BasicBlocks &temp_obj) = delete;
        BasicBlocks &operator=(const BasicBlocks &temp_obj) = delete;

        /// @brief Destructor of the BasicBlocks, we need
        /// to free the memory
        ~BasicBlocks() = default;

        /// @brief Return the number of basic blocks in the graph
        /// @return number of basic blocks
        size_t get_number_of_basic_blocks() const;

        /// @brief Add a node to the list of predecessors of another
        /// @param node node to add predecessor
        /// @param pred predecessor node
        void add_predecessor(DVMBasicBlock *node, DVMBasicBlock *pred);

        /// @brief Add a node to the list of successors of another
        /// @param node node to add sucessor
        /// @param suc sucessor node
        void add_sucessor(DVMBasicBlock *node, DVMBasicBlock *suc);

        /// @brief Add a node to the vector of nodes, we will transfer the
        /// ownership
        /// @param node node to push into our vector
        void add_node(DVMBasicBlock *node);

        /// @brief Add an edge to the basic blocks
        /// @param src source node
        /// @param dst edge node
        void add_edge(DVMBasicBlock *src, DVMBasicBlock *dst);

        /// @brief Get the node type between JOIN_NODE, BRANCH_NODE or REGULAR_NODE
        /// @param node node to check
        /// @return type of node
        node_type_t get_node_type(DVMBasicBlock *node);

        /// @brief Remove a node from the graph, this operation can
        /// be expensive on time
        /// @param node node to remove
        void remove_node(DVMBasicBlock *node);

        /// @brief Get a basic block given an idx, the idx can be one
        /// address from the first to the last address of the block
        /// @param idx address of the block to retrieve
        /// @return block that contains an instruction in that address
        DVMBasicBlock *get_basic_block_by_idx(std::uint64_t idx);

        std::string toString();
    };

    /// @brief specification of a field analysis
    class FieldAnalysis {
    private:
        /// @brief Encoded field or ExternalField that contains the information of the Field
        std::variant<parser::dex::EncodedField *,
                     ExternalField *>
                field;

        /// @brief boolean saying if it is external
        bool external;
        /// @brief name of the field
        std::string_view name;
        /// @brief xrefs where field is read
        class_method_idx_t xrefread;
        /// @brief xrefs where field is written
        class_method_idx_t xrefwrite;

    public:
        FieldAnalysis(parser::dex::EncodedField *field);

        FieldAnalysis(ExternalField *field);

        ~FieldAnalysis() = default;

        bool is_external() const;

        parser::dex::EncodedField *get_encoded_field() const;

        ExternalField *get_external_field() const;

        std::string_view get_name();

        iterator_range<class_method_idx_iterator_t> get_xrefread();

        iterator_range<class_method_idx_iterator_t> get_xrefwrite();

        /// @brief Add a cross reference where the field is read in code
        /// @param c class where is read
        /// @param m method where is read
        /// @param offset idx where is read
        void add_xrefread(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset);

        /// @brief Add a cross reference where the field is written in code
        /// @param c class where is written
        /// @param m method where is written
        /// @param offset idx where is written
        void add_xrefwrite(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset);
    };

    /// @brief specification of a string analysis
    class StringAnalysis {
    private:
        /// @brief Value of the string
        std::string_view value;
        /// @brief xref where the string is used
        class_method_idx_t xreffrom;

    public:
        StringAnalysis(std::string_view value);

        ~StringAnalysis() = default;

        iterator_range<class_method_idx_iterator_t> get_xreffrom();

        /// @brief Add a cross reference where the string is read
        /// @param c class where is read
        /// @param m method where is read
        /// @param offset offset where is read
        void add_xreffrom(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset);
    };

    /// @brief Specification of the method analysis, a method contains
    /// instructions, exceptions data, and so on...
    class MethodAnalysis {
    public:
        /// @brief vector of known apis of Android
        const std::vector<std::string_view> known_apis{
                "Landroid/", "Lcom/android/internal/util", "Ldalvik/", "Ljava/", "Ljavax/", "Lorg/apache/",
                "Lorg/json/", "Lorg/w3c/dom/", "Lorg/xml/sax", "Lorg/xmlpull/v1/", "Ljunit/", "Landroidx/"};

    private:
        /// @brief Internal method is external or internal?
        bool is_external = false;

        /// @brief encoded method or external method
        std::variant<
                shuriken::parser::dex::EncodedMethod *,
                ExternalMethod *>
                method_encoded;

        /// @brief name of the method, store it to avoid
        /// asking one again, and again, and again
        std::string_view name;

        /// @brief descriptor of the method
        std::string_view description;

        /// @brief Access flags from the method
        shuriken::dex::TYPES::access_flags access_flags;

        /// @brief class name
        std::string_view class_name;

        /// @brief full name of the method in dalvik format
        std::string_view full_name;

        /// @brief object with the disassembled method
        shuriken::disassembler::dex::DisassembledMethod *disassembled;

        /// @brief basic blocks from the method
        BasicBlocks basic_blocks;

        /// @brief fields read in the method
        class_field_idx_t xrefread;
        /// @brief fields written in the method
        class_field_idx_t xrefwrite;

        /// @brief methods called from the current method
        class_method_idx_t xrefto;
        /// @brief methods that call the current method
        class_method_idx_t xreffrom;

        /// @brief new instance of the method
        class_idx_t xrefnewinstance;
        /// @brief use of const class
        class_idx_t xrefconstclass;

        /// @brief cache of method string
        std::string method_string;

        /**** Private Methods ****/
        /// @brief Pretty print an instruction and its opcodes in a dot format to an output dot file
        /// @param dot_file file where to dump the instruction
        /// @param instr instruction to dump to dot file
        void dump_instruction_dot(std::ofstream &dot_file, disassembler::dex::Instruction *instr);

        /// @brief Pretty print a basic block in a dot graph
        /// @param dot_file file where to dump the basic block
        /// @param bb basic block to dump to dot file
        void dump_block_dot(std::ofstream &dot_file, DVMBasicBlock *bb);

        /// @brief Pretty print a method in a dot graph
        /// @param dot_file file where to dump the basic block
        /// @param name name of the dot file
        void dump_method_dot(std::ofstream &dot_file);

        /// @brief Some kind of magic function that will take all
        /// the instructions from the method, and after some wololo
        /// will generate the basic blocks.
        void create_basic_blocks();

    public:
        MethodAnalysis(shuriken::parser::dex::EncodedMethod *encoded_method,
                       shuriken::disassembler::dex::DisassembledMethod *disassembled);

        MethodAnalysis(ExternalMethod *external_method);

        /// @brief Dump the method as a dot file into
        /// the current path
        /// @param file_path reference to a path where
        /// to dump the content
        void dump_dot_file(std::string &file_path);

        /// @brief Check if the method is external
        /// @return method external
        bool external() const;

        /// @return Basic blocks of the method with the CFG
        BasicBlocks &get_basic_blocks();

        /// @return Disassembled method object which contains the instructions
        shuriken::disassembler::dex::DisassembledMethod *get_disassembled_method();

        /// @brief Check if current method is an android api
        /// @return is android api method
        bool is_android_api() const;

        /// @return name of the method
        std::string_view get_name() const;

        /// @return descriptor of the method
        std::string_view get_descriptor() const;

        /// @return access flags of the method
        shuriken::dex::TYPES::access_flags get_access_flags() const;

        /// @return name of the class the method belongs to
        std::string_view get_class_name() const;

        /// @return full name of the method in Dalvik Format
        std::string_view get_full_name() const;

        std::string_view toString();

        /// @brief Retrieve a pointer to an instruction by a given address
        /// @param addr address of the instruction to retrieve
        /// @return pointer to instruction or nullptr
        shuriken::disassembler::dex::Instruction *get_instruction_by_addr(std::uint64_t addr);

        /// @return iterator to the instructions from the method
        shuriken::disassembler::dex::it_instructions instructions();

        /// @return get the encoded method internal of the MethodAnalysis
        shuriken::parser::dex::EncodedMethod *get_encoded_method();

        /// @return get the ExternalMethod internal of the MethodAnalysis
        ExternalMethod *get_external_method();

        /// @return iterator for the fields that are read in the method
        iterator_range<class_field_idx_iterator_t> get_xrefread();

        /// @return iterator for the fields that are written in the method
        iterator_range<class_field_idx_iterator_t> get_xrefwrite();

        /// @return iterator for the methods called from the current method
        iterator_range<class_method_idx_iterator_t> get_xrefto();

        /// @return iterator for the methods that call the current method
        iterator_range<class_method_idx_iterator_t> get_xreffrom();

        /// @return iterator of new instance of classes in the method
        iterator_range<class_idx_iterator_t> get_xrefnewinstance();

        /// @return iterator of constant classes used in the method
        iterator_range<class_idx_iterator_t> get_xrefconstclass();

        /// @brief Add a new cross-reference where a field is read in the method
        void add_xrefread(ClassAnalysis *c, FieldAnalysis *f, std::uint64_t offset);

        /// @brief Add a new cross-reference where a field is written in the method
        void add_xrefwrite(ClassAnalysis *c, FieldAnalysis *f, std::uint64_t offset);

        /// @brief Add a new cross-reference of a method called from this method
        void add_xrefto(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset);

        /// @brief Add a new cross-reference of a method that calls this method
        void add_xreffrom(ClassAnalysis *c, MethodAnalysis *m, std::uint64_t offset);

        /// @brief Add a cross-reference of a new object instance in this method
        void add_xrefnewinstance(ClassAnalysis *c, std::uint64_t offset);

        /// @brief Add a cross-reference of a const class used in this method
        void add_xrefconstclass(ClassAnalysis *c, std::uint64_t offset);
    };

    /// @brief Specification of the class analysis, this class contains
    /// fields, strings, methods...
    class ClassAnalysis {
        using id_method_t = std::unordered_map<std::string_view, MethodAnalysis *>;
        using id_method_iterator_t = id_method_t::iterator;

        using id_field_t = std::unordered_map<std::string_view, std::unique_ptr<FieldAnalysis>>;
        using id_field_iterator_t = id_field_t::iterator;

    private:
        /// @brief definition of the class, it can be a class
        /// from the dex or an external class
        std::variant<shuriken::parser::dex::ClassDef *, ExternalClass *> class_def;

        /// @brief is an external class
        bool is_external;

        /// @brief name of the class that it extends
        std::string_view extends_;

        /// @brief cache to name of the class
        std::string_view name_;

        // Vector of methods with unique ownership
        std::unordered_map<std::string_view, MethodAnalysis *> methods;
        /// @brief Map for the FieldAnalysis
        std::unordered_map<std::string_view, std::unique_ptr<FieldAnalysis>> fields;

        /// @brief Classes that this class calls
        classxref_t xrefto;
        /// @brief Classes that call this class
        classxref_t xrefsfrom;

        /// @brief New instance of this class
        std::vector<std::pair<MethodAnalysis *, std::uint64_t>> xrefnewinstance;

        /// @brief use of const class of this class
        std::vector<std::pair<MethodAnalysis *, std::uint64_t>> xrefconstclass;

    public:
        ClassAnalysis(shuriken::parser::dex::ClassDef *class_def);

        ClassAnalysis(ExternalClass *class_def);

        /// @brief add a method to the current class
        /// @param method_analysis method to include in the class
        void add_method(MethodAnalysis *method_analysis);

        /// @return number of methods from the class
        size_t get_nb_methods() const;

        /// @return number of fields from the class
        size_t get_nb_fields() const;

        /// @return a pointer to ClassDef or nullptr if external
        shuriken::parser::dex::ClassDef *get_classdef();

        /// @return a pointer to ExternalClass or nullptr if not external
        ExternalClass *get_externalclass();

        /// @brief Is the current class an external class?
        /// @return class is external
        bool is_class_external() const;

        /// @return name of the class the current class extends
        std::string_view extends();

        /// @return name of the class
        std::string_view name();

        /// @brief Return a vector of implemented interfaces, in
        /// the case of external class raise exception
        /// @return implemented interfaces
        shuriken::parser::dex::ClassDef::it_interfaces_list implements();

        /// @return iterator to the methods from the class
        iterator_range<id_method_iterator_t> get_methods();

        /// @brief Given an Encoded or ExternalMethod returns a MethodAnalysis pointer
        /// @param method method to look for
        /// @return MethodAnalysis pointer
        MethodAnalysis *get_method_analysis(
                std::variant<shuriken::parser::dex::EncodedMethod *, ExternalMethod *> method);

        /// @return iterator to the fields from the class
        iterator_range<id_field_iterator_t> get_fields();

        /// @brief Given an encoded field return a FieldAnalysis pointer
        /// @param field field to look for
        /// @return FieldAnalysis pointer
        FieldAnalysis *get_field_analysis(shuriken::parser::dex::EncodedField *field);

        /// @brief Given an encoded field return a FieldAnalysis pointer
        /// @param field field to look for
        /// @return FieldAnalysis pointer
        FieldAnalysis *get_field_analysis(ExternalField *field);


        /// @brief Add a cross reference of a field read
        void add_field_xref_read(MethodAnalysis *method,
                                 ClassAnalysis *classobj,
                                 std::variant<shuriken::parser::dex::EncodedField *,
                                              ExternalField *>
                                         field,
                                 std::uint64_t off);

        /// @brief Add a cross reference of a field write
        void add_field_xref_write(MethodAnalysis *method,
                                  ClassAnalysis *classobj,
                                  std::variant<shuriken::parser::dex::EncodedField *,
                                               ExternalField *>
                                          field,
                                  std::uint64_t off);

        /// @brief Add a cross reference of a method called to
        void add_method_xref_to(MethodAnalysis *method1,
                                ClassAnalysis *classobj,
                                MethodAnalysis *method2,
                                std::uint64_t off);

        /// @brief Add a cross reference of a method called from
        void add_method_xref_from(MethodAnalysis *method1,
                                  ClassAnalysis *classobj,
                                  MethodAnalysis *method2,
                                  std::uint64_t off);
        /// @brief Add xref to another class
        void add_xref_to(shuriken::dex::TYPES::ref_type ref_kind,
                         ClassAnalysis *classobj,
                         MethodAnalysis *methodobj,
                         std::uint64_t offset);
        /// @brief Add xref from another class
        void add_xref_from(shuriken::dex::TYPES::ref_type ref_kind,
                           ClassAnalysis *classobj,
                           MethodAnalysis *methodobj,
                           std::uint64_t offset);

        void add_xref_new_instance(MethodAnalysis *methodobj, std::uint64_t offset);

        void add_xref_const_class(MethodAnalysis *methodobj, std::uint64_t offset);

        iterator_range<classxref_t::iterator> get_xrefto();

        iterator_range<classxref_t::iterator> get_xrefsfrom();

        iterator_range<std::vector<std::pair<MethodAnalysis *, std::uint64_t>>::iterator> get_xrefnewinstance();

        iterator_range<std::vector<std::pair<MethodAnalysis *, std::uint64_t>>::iterator> get_xrefconstclass();
    };
}// namespace shuriken::analysis::dex

#endif//SHURIKENPROJECT_DEX_ANALYSIS_H
