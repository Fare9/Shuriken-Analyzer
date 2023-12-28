//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file annotations.h
// @brief Information about annotations in the DEX file, this is information
// from the compiler that can be used, for example, for debugging.

#ifndef SHURIKENLIB_ANNOTATIONS_H
#define SHURIKENLIB_ANNOTATIONS_H

#include "shuriken/common/iterator_range.h"
#include "shuriken/common/shurikenstream.h"

#include <memory>
#include <unordered_map>

namespace shuriken {
    namespace parser {
        namespace dex {

            /// @brief Information for the list of annotations for the parameters
            struct ParameterAnnotation {
                /// @brief idx of method for the annotations
                std::uint32_t method_idx;
                /// @brief offset where annotations are
                std::uint32_t annotations_off;
            };

            /// @brief Information for the list of annotations for the methods
            struct MethodAnnotation {
                /// @brief idx of the associated method
                std::uint32_t method_idx;
                /// @brief Offset to the annotations of the method
                std::uint32_t annotations_off;
            };

            /// @brief Information for the list of annotations for the fields
            struct FieldAnnotation {
                /// @brief Field IDX of the annotation
                std::uint32_t field_idx;
                /// @brief Offset to the annotations
                std::uint32_t annotations_off;
            };

            /// @brief Class with all the annotations
            class AnnotationDirectoryItem
            {
            public:
                using field_annotations_id_t = std::unordered_map<std::uint32_t, FieldAnnotation>;
                using method_annotations_id_t = std::unordered_map<std::uint32_t, MethodAnnotation>;
                using parameter_annotations_id_t = std::unordered_map<std::uint32_t, ParameterAnnotation>;

                using it_field_annotations = iterator_range<field_annotations_id_t::iterator>;
                using it_method_annotations = iterator_range<method_annotations_id_t::iterator>;
                using it_parameter_annotations = iterator_range<parameter_annotations_id_t::iterator>;

            private:
                /// @brief Offset to the annotations of the class
                std::uint32_t class_annotations_off;
                /// @brief field annotations by id
                field_annotations_id_t field_annotations_by_id;
                /// @brief method annotations by id
                method_annotations_id_t method_annotations_by_id;
                /// @brief parameter annotations by id
                parameter_annotations_id_t parameter_annotations_by_id;

            public:
                /// @brief Constructor for AnnotationDirectoryItem, default one
                AnnotationDirectoryItem() = default;
                /// @brief Destructor for AnnotationDirectoryItem, default one
                ~AnnotationDirectoryItem() = default;

                /// @brief Parse the annotation directory item
                /// @param stream stream with the DEX file
                void parse_annotation_directory_item(common::ShurikenStream& stream);

                it_field_annotations get_field_annotations() {
                    return make_range(field_annotations_by_id.begin(), field_annotations_by_id.end());
                }

                it_method_annotations get_method_annotations() {
                    return make_range(method_annotations_by_id.begin(), method_annotations_by_id.end());
                }

                it_parameter_annotations get_parameter_annotations() {
                    return make_range(parameter_annotations_by_id.begin(), parameter_annotations_by_id.end());
                }

                FieldAnnotation& get_field_annotation_by_id(std::uint32_t field_id) {
                    if (!field_annotations_by_id.contains(field_id))
                        throw std::runtime_error("Error field_id provided has no annotation");
                    return field_annotations_by_id[field_id];
                }

                MethodAnnotation& get_method_annotation_by_id(std::uint32_t method_id) {
                    if (!method_annotations_by_id.contains(method_id))
                        throw std::runtime_error("Error method_id provided has no annotation");
                    return method_annotations_by_id[method_id];
                }

                ParameterAnnotation& get_parameter_annotation_by_id(std::uint32_t method_id) {
                    if (!parameter_annotations_by_id.contains(method_id))
                        throw std::runtime_error("Error method_id provided has no annotation");
                    return parameter_annotations_by_id[method_id];
                }
            };
        }
    }
}

#endif //SHURIKENLIB_ANNOTATIONS_H
