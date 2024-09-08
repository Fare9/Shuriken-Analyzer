//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file annotations.cpp

#include "shuriken/parser/Dex/dex_annotations.h"
#include "shuriken/common/logger.h"

using namespace shuriken::parser::dex;

void AnnotationDirectoryItem::parse_annotation_directory_item(common::ShurikenStream &stream) {
    auto current_offset = stream.tellg();

    size_t I;
    std::uint32_t fields_size;
    std::uint32_t annotated_methods_size;
    std::uint32_t annotated_parameters_size;
    std::uint32_t idx, annotations_off;

    log(LEVEL::MYDEBUG, "Started parsing of annotations");

    // first read the offset
    stream.read_data<std::uint32_t>(class_annotations_off, sizeof(std::uint32_t));
    // then read the sizes
    stream.read_data<std::uint32_t>(fields_size, sizeof(std::uint32_t));
    stream.read_data<std::uint32_t>(annotated_methods_size, sizeof(std::uint32_t));
    stream.read_data<std::uint32_t>(annotated_parameters_size, sizeof(std::uint32_t));

    for (I = 0; I < fields_size; ++I) {
        stream.read_data<std::uint32_t>(idx, sizeof(std::uint32_t));
        stream.read_data<std::uint32_t>(annotations_off, sizeof(std::uint32_t));
        field_annotations_by_id[idx] = {.field_idx = idx, .annotations_off = annotations_off};
    }

    for (I = 0; I < annotated_methods_size; ++I) {
        stream.read_data<std::uint32_t>(idx, sizeof(std::uint32_t));
        stream.read_data<std::uint32_t>(annotations_off, sizeof(std::uint32_t));
        method_annotations_by_id[idx] = {.method_idx = idx, .annotations_off = annotations_off};
    }

    for (I = 0; I < annotated_parameters_size; ++I) {
        stream.read_data<std::uint32_t>(idx, sizeof(std::uint32_t));
        stream.read_data<std::uint32_t>(annotations_off, sizeof(std::uint32_t));
        parameter_annotations_by_id[idx] = {.method_idx = idx, .annotations_off = annotations_off};
    }

    log(LEVEL::MYDEBUG, "Finished parsing of annotations");

    stream.seekg(current_offset, std::ios_base::beg);
}

AnnotationDirectoryItem::it_field_annotations AnnotationDirectoryItem::get_field_annotations() {
    return make_range(field_annotations_by_id.begin(), field_annotations_by_id.end());
}

AnnotationDirectoryItem::it_method_annotations AnnotationDirectoryItem::get_method_annotations() {
    return make_range(method_annotations_by_id.begin(), method_annotations_by_id.end());
}

AnnotationDirectoryItem::it_parameter_annotations AnnotationDirectoryItem::get_parameter_annotations() {
    return make_range(parameter_annotations_by_id.begin(), parameter_annotations_by_id.end());
}

FieldAnnotation &AnnotationDirectoryItem::get_field_annotation_by_id(std::uint32_t field_id) {
    if (!field_annotations_by_id.contains(field_id))
        throw std::runtime_error("Error field_id provided has no annotation");
    return field_annotations_by_id[field_id];
}

MethodAnnotation &AnnotationDirectoryItem::get_method_annotation_by_id(std::uint32_t method_id) {
    if (!method_annotations_by_id.contains(method_id))
        throw std::runtime_error("Error method_id provided has no annotation");
    return method_annotations_by_id[method_id];
}

ParameterAnnotation &AnnotationDirectoryItem::get_parameter_annotation_by_id(std::uint32_t method_id) {
    if (!parameter_annotations_by_id.contains(method_id))
        throw std::runtime_error("Error method_id provided has no annotation");
    return parameter_annotations_by_id[method_id];
}