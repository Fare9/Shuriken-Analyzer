//--------------------------------------------------------------------*- C++ -*-
// Shuriken-Analyzer: library for bytecode analysis.
// @author Farenain <kunai.static.analysis@gmail.com>
//
// @file deref_iterator_range.h
// @brief Utility to create an iterator for std::reference_wrapper types
// so we can use them in

#ifndef SHURIKENPROJECT_DEREF_ITERATOR_RANGE_H
#define SHURIKENPROJECT_DEREF_ITERATOR_RANGE_H

#include <functional>
#include <iostream>
#include <iterator>// For std::iterator_traits
#include <list>
#include <vector>

namespace shuriken {
    /// is_reference_wrapper returns false for any type
    template<typename T>
    struct is_reference_wrapper : std::false_type {};

    /// and true for those types which are std::reference_wrapper
    template<typename U>
    struct is_reference_wrapper<std::reference_wrapper<U>> : std::true_type {};

    // Trait to check if a container's value type is std::reference_wrapper
    template<typename T, typename = void>
    struct is_container_of_reference_wrapper : std::false_type {};

    template<typename T>
    struct is_container_of_reference_wrapper<T, std::void_t<typename T::value_type>>
        : is_reference_wrapper<typename T::value_type> {};

    // Custom iterator to unpack std::reference_wrapper
    template<typename T>
    struct deref_iterator_range {
        static_assert(is_container_of_reference_wrapper<T>::value,
                      "T must be a container of std::reference_wrapper");

        struct iterator {
            using iterator_category = std::bidirectional_iterator_tag;
            using value_type = typename T::value_type::type;
            using difference_type = typename std::iterator_traits<typename T::iterator>::difference_type;
            using pointer = value_type *;
            using reference = value_type &;

            typename T::iterator it;

            iterator &operator++() {
                ++it;
                return *this;
            }

            iterator &operator--() {
                --it;
                return *this;
            }

            reference operator*() {
                return it->get();
            }

            pointer operator->() {
                return &it->get();
            }

            bool operator!=(const iterator &other) const {
                return it != other.it;
            }

            bool operator==(const iterator &other) const {
                return it == other.it;
            }
        };

        deref_iterator_range(T &container) : t(container) {}

        T &t;

        iterator begin() const {
            return {t.begin()};
        }

        iterator end() const {
            return {t.end()};
        }
    };
}// namespace shuriken

#endif//SHURIKENPROJECT_DEREF_ITERATOR_RANGE_H
