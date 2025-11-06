# Contributing to IOI SDK

Thank you for considering contributing to IOI SDK! This document outlines the process for contributing to the project.

## Development Environment

We recommend using VS Code with Dev Containers for development. This ensures a consistent environment for all contributors.

1. Install [VS Code](https://code.visualstudio.com/) and the [Remote Containers](https://marketplace.visualstudio.com/items?itemName=ms-vscode-remote.remote-containers) extension
2. Clone the repository
3. Open the project in VS Code
4. When prompted, click "Reopen in Container"

Alternatively, you can set up your local environment:

1. Install Rust (stable channel)
2. Run `./dev-setup.sh` to install dependencies

## Development Workflow

1. Fork the repository
2. Create a new branch for your feature or bug fix
3. Make your changes
4. Ensure all tests pass with `cargo test`
5. Ensure code formatting is correct with `cargo fmt --all -- --check`
6. Ensure no clippy warnings with `cargo clippy --all-targets --all-features -- -D warnings`
7. Submit a pull request

## Bottom-Up Architecture

When implementing new features, follow the "bottom-up" approach:

1. Start with the foundational layers (core traits, cryptographic primitives)
2. Build higher-level components on top of these foundations
3. Ensure each layer has a well-defined API and thorough tests

## Coding Standards

- Follow Rust's official [style guidelines](https://doc.rust-lang.org/1.0.0/style/README.html)
- Use meaningful variable and function names
- Add comments explaining complex logic
- Write comprehensive unit tests
- Document public API with rustdoc comments

## Commit Messages

Follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat`: A new feature
- `fix`: A bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code changes that neither fix bugs nor add features
- `perf`: Performance improvements
- `test`: Adding or fixing tests
- `chore`: Changes to the build process or auxiliary tools

## Pull Request Process

1. Update documentation for any changed functionality
2. Add or update tests for your changes
3. Ensure all CI checks pass
4. Request review from maintainers
5. Address any feedback from code review

## License

By contributing to IOI SDK, you agree that your contributions will be licensed under both the MIT and Apache 2.0 licenses.
