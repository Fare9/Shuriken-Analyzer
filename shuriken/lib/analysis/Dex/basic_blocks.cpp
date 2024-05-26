//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file dex_analysis.cpp

#include "shuriken/analysis/Dex/dex_analysis.h"
#include <iomanip>
#include <sstream>

using namespace shuriken::analysis::dex;

// ---------------------- DVMBasicBlock ----------------------

DVMBasicBlock::DVMBasicBlock(read_instructions_t instructions_)
    : instructions_(instructions_) {
}

size_t DVMBasicBlock::get_nb_instructions() const {
    return instructions_.size();
}

DVMBasicBlock::read_instructions_t DVMBasicBlock::get_instructions() {
    return instructions_;
}

shuriken::disassembler::dex::Instruction *DVMBasicBlock::get_terminator() {
    if (instructions_.empty())
        return nullptr;
    return instructions_.back();
}

std::uint64_t DVMBasicBlock::get_first_address() const {
    if (instructions_.empty())
        throw std::runtime_error("Error, basic block does not contain any instruction");
    return instructions_.front()->get_address();
}

std::uint64_t DVMBasicBlock::get_last_address() const {
    if (instructions_.empty())
        throw std::runtime_error("Error, basic block does not contain any instruction");
    return instructions_.back()->get_address();
}

std::string_view DVMBasicBlock::get_name() {
    if (!name.empty())
        return name;

    name = "BB.";
    name += std::to_string(get_first_address()) + "-";
    name += std::to_string(get_last_address());
    return name;
}

bool DVMBasicBlock::is_try_block() const {
    return try_block;
}

void DVMBasicBlock::set_try_block(bool try_block) {
    this->try_block = try_block;
}

bool DVMBasicBlock::is_catch_block() const {
    return catch_block;
}

void DVMBasicBlock::set_catch_block(bool catch_block) {
    this->catch_block = catch_block;
}

shuriken::parser::dex::DVMType *DVMBasicBlock::get_handler_type() {
    return handler_type;
}

void DVMBasicBlock::set_handler_type(shuriken::parser::dex::DVMType *handler) {
    this->handler_type = handler;
}

std::string DVMBasicBlock::toString() {
    if (block_string.empty()) {
        std::stringstream ss;
        ss << get_name().data() << '\n';
        if (is_try_block())
            ss << ".try_block" << '\n';
        else if (is_catch_block())
            ss << ".catch_block" << '\n';
        for (disassembler::dex::Instruction *insn: instructions_) {
            ss << std::hex << std::setw(8)
               << std::setfill('0')
               << insn->get_address()
               << ' ' << insn->print_instruction() << '\n';
        }
        block_string = ss.str();
    }
    return block_string;
}


shuriken::iterator_range<BasicBlocks::nodesiterator_t> BasicBlocks::nodes() {
    return make_range(nodes_.begin(), nodes_.end());
}

shuriken::iterator_range<BasicBlocks::reversenodesiterator_t> BasicBlocks::reverse_nodes() {
    return make_range(nodes_.rbegin(), nodes_.rend());
}

shuriken::iterator_range<BasicBlocks::edgesiterator_t> BasicBlocks::edges() {
    return make_range(edges_.begin(), edges_.end());
}

shuriken::iterator_range<BasicBlocks::reverseedgesiterator_t> BasicBlocks::reverse_edges() {
    return make_range(edges_.rbegin(), edges_.rend());
}

shuriken::iterator_range<BasicBlocks::nodesetiterator_t> BasicBlocks::successors(DVMBasicBlock *node) {
    if (successors_.find(node) == successors_.end())
        throw std::runtime_error("Given node has no successors");
    return make_range(successors_[node].begin(), successors_[node].end());
}

shuriken::iterator_range<BasicBlocks::nodesetiterator_t> BasicBlocks::predecessors(DVMBasicBlock *node) {
    if (predecessors_.find(node) == predecessors_.end())
        throw std::runtime_error("Given node has no predecessors");
    return make_range(predecessors_[node].begin(), predecessors_[node].end());
}

shuriken::iterator_range<BasicBlocks::reversenodesetiterator_t> BasicBlocks::reverse_successors(DVMBasicBlock *node) {
    if (successors_.find(node) == successors_.end())
        throw std::runtime_error("Given node has no successors");
    return make_range(successors_[node].rbegin(), successors_[node].rend());
}

shuriken::iterator_range<BasicBlocks::reversenodesetiterator_t> BasicBlocks::reverse_predecessors(DVMBasicBlock *node) {
    if (predecessors_.find(node) == predecessors_.end())
        throw std::runtime_error("Given node has no predecessors");
    return make_range(predecessors_[node].rbegin(), predecessors_[node].rend());
}

// ---------------------- BasicBlocks ----------------------

size_t BasicBlocks::get_number_of_basic_blocks() const {
    return nodes_.size();
}

void BasicBlocks::add_predecessor(DVMBasicBlock *node, DVMBasicBlock *pred) {
    predecessors_[node].insert(pred);
}

void BasicBlocks::add_sucessor(DVMBasicBlock *node, DVMBasicBlock *suc) {
    successors_[node].insert(suc);
}

void BasicBlocks::add_node(DVMBasicBlock *node) {
    if (std::find(nodes_.begin(), nodes_.end(), node) == nodes_.end())
        nodes_.push_back(node);
}

void BasicBlocks::add_edge(DVMBasicBlock *src, DVMBasicBlock *dst) {
    add_node(src);
    add_node(dst);

    // now insert the edge
    auto edge_pair = std::make_pair(src, dst);
    /// check if edge already exists
    auto it = std::find_if(edges_.begin(), edges_.end(), [&](std::pair<DVMBasicBlock *, DVMBasicBlock *> &edge) {
        return (edge_pair.first == edge.first) && (edge_pair.second == edge.second);
    });

    /// if not, add it
    if (it == edges_.end()) {
        edges_.push_back(edge_pair);
        /// now add the successors and predecessors
        add_sucessor(src, dst);
        add_predecessor(dst, src);
    }
}

BasicBlocks::node_type_t BasicBlocks::get_node_type(DVMBasicBlock *node) {
    if (predecessors_[node].size() > 1)
        return JOIN_NODE;
    else if (successors_[node].size() > 1)
        return BRANCH_NODE;
    else
        return REGULAR_NODE;
}

void BasicBlocks::remove_node(DVMBasicBlock *node) {
    // with this we provide RAII
    std::unique_ptr<DVMBasicBlock> const node_(node);

    if (std::find(nodes_.begin(), nodes_.end(), node) == nodes_.end())
        throw std::runtime_error("remove_mode: given node does not exist in graph");

    auto node_type = get_node_type(node);

    if (node_type == JOIN_NODE)// len(predecessors) > 1
    {
        auto suc = *successors_[node].begin();

        // delete from predecessors of sucessor
        predecessors_[suc].erase(node);
        // remove the edge
        std::ranges::remove(edges_, std::make_pair(node, suc));

        for (auto pred: predecessors_[node]) {
            // delete the edge from predecessor to the node
            std::ranges::remove(edges_, std::make_pair(pred, node));
            // delete from successors[pred] the node
            successors_[pred].erase(node);
        }

        for (auto pred: predecessors_[node]) {
            // now add new one with successor
            edges_.emplace_back(pred, suc);
            // add the predecessor of sucesspr
            predecessors_[suc]
                    .insert(pred);
            // add the successor of pred
            successors_[pred].insert(suc);
        }
    } else if (node_type == BRANCH_NODE)// len(successors) > 1
    {
        auto pred = *predecessors_[node].begin();

        // delete from successors of pred
        successors_[pred].erase(node);
        // remove the edge
        std::ranges::remove(edges_, std::make_pair(pred, node));

        // now disconnect the node from the successors
        for (auto suc: successors_[node]) {
            // remove the edges node->suc
            std::ranges::remove(edges_, std::make_pair(node, suc));
            // remove the node as predecessor of this successor
            predecessors_[suc].erase(node);
        }

        for (auto suc: successors_[node]) {
            // add the edges
            edges_.emplace_back(pred, suc);
            // add the predecessor of sucesspr
            predecessors_[suc].insert(pred);
            // add the sucessor of pred
            successors_[pred].insert(suc);
        }
    } else {
        DVMBasicBlock *pred, *suc;
        if (predecessors_[node].size() == 1) {
            pred = *predecessors_[node].begin();

            // delete from successors of pred
            successors_[pred].erase(node);
            // remove the edge
            std::ranges::remove(edges_, std::make_pair(pred, node));
        }

        if (successors_[node].size() == 1) {
            auto suc = *successors_[node].begin();

            // delete from predecessors of sucessor
            predecessors_[suc].erase(node);
            // remove the edge
            std::ranges::remove(edges_, std::make_pair(node, suc));
        }

        if (pred != nullptr && suc != nullptr) {
            edges_.emplace_back(pred, suc);
            // add sucessor to pred
            successors_[pred].insert(suc);
            // add predecessor to suc
            predecessors_[suc].insert(pred);
        }
    }

    // now delete the node from the predecessors and successors
    predecessors_.erase(node);
    successors_.erase(node);

    // finally delete from vector
    std::ranges::remove(nodes_, node);
}

DVMBasicBlock *BasicBlocks::get_basic_block_by_idx(std::uint64_t idx) {
    auto it = std::find_if(nodes_.begin(), nodes_.end(), [&](DVMBasicBlock *bb) -> bool {
        return bb->get_first_address() >= idx && bb->get_last_address() <= idx;
    });

    if (it == nodes_.end()) return nullptr;
    return *it;
}

std::string BasicBlocks::toString() {
    if (basic_blocks_string.empty()) {
        std::stringstream ss;
        for (DVMBasicBlock* dvmBasicBlock : nodes_) {
            ss << dvmBasicBlock->toString() << '\n';
        }
        basic_blocks_string = ss.str();
    }
    return basic_blocks_string;
}