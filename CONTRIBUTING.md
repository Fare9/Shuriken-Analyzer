# Contributing to Shuriken Analyzer

We welcome contributions into Shuriken Analyzer, this file must provide you with a few key points about the best way to contribute to the project, including some guidelines, coding style guides and how to work in an issue.

## Code Style Guidelines

We will follow some of the recommendations from the [LLVM Coding Standards](https://llvm.org/docs/CodingStandards.html), also for people new at C++ programming who want to contribute, they can read the [CppCoreGuidelines](https://isocpp.github.io/CppCoreGuidelines/CppCoreGuidelines). But mostly I think the next bullet points can be followed for this project:

- Use `snake_case` for variable and function names.
- Use `PascalCase` for class and struct names.
- Use `UPPERCASE_WITH_UNDERSCORES` for macros.
- Use spaces instead of tabs, with a tab width of 4 spaces.
- Use C++11 style of initializing variables, i.e., `int x{5}` instead of `int x = 5`.
- Use smart pointers (`std::unique_ptr`, `std::shared_ptr`) instead of raw pointers whenever possible.
- Use `nullptr` instead of `NULL`.
- Use include guards in the header files, these include guards must follow the next convention: `SHURIKEN_<Folder1>_<Folder2>_<FolderN>_<FileName>_HPP`.
- For initializing `maps` or `lists` with many values, try to use a table definition file, and an include for expanding the values at compilation time (it makes code more clear and smaller).
- This project uses C++20, so all the APIs available can be used.

## How to work in the project?

Commits in master should be explanatory of the features included or the problems fixed. Also, we will try to keep the number of commits as low as possible. We will work by issues, so if an issue for a new feature or a bug does not exist, create it and work from there. Let's explain this:

- If an issue exist

If an issue already exist, it is possible to create a branch in the `Development` section on the right side of the issue webpage. Create a branch that will automatically have the name of the issue. Work on it and finally create a pull request to the main branch.

- If an issue does not exist

If you find a bug, or miss a feature in Shuriken, create an issue with a meaningful name, and then write a proper description. After that, if you want to work on the issue, follow the previous point.

## How to write commits

We will try to keep the number of commits in the main branch as low as possible, so while you are working in a branch you can create as many commits as you need, but once you are going to create a pull request for the `main` branch, squash all the related commits into just one or just a few commits, in that way, it will be easier to review and we will keep the number of commits in `main` as low as possible. If you don't know about this, I recommend you to read the next [post](https://www.git-tower.com/learn/git/faq/git-squash) about `git squash`.

## Code of Conduct

By participating in this project, you agree to abide by the Code of Conduct.

If you have any questions or issues, please open an issue in the project repository or contact one of the project maintainers.