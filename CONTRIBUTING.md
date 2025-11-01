# Contributing to Composite Provider

Thank you for your interest in contributing to the Composite Provider project!

## How to Contribute

### Reporting Issues

If you find a bug or have a feature request:
1. Check if the issue already exists
2. Create a new issue with a clear description
3. Include relevant details (OS, OpenSSL version, etc.)

### Code Contributions

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass (`make test`)
6. Commit your changes with clear messages
7. Push to your fork
8. Create a Pull Request

## Development Guidelines

### Code Style

- Follow C99 standard
- Use clear, descriptive variable names
- Add comments for complex logic
- Keep functions focused and small
- Handle errors gracefully

### Testing

- All new features must include tests
- Existing tests must continue to pass
- Use the test framework in `tests/`

### Building

Before submitting:
```bash
make clean
make
make test
```

All builds should complete without warnings or errors.

### Security

- Report security vulnerabilities privately
- Follow secure coding practices
- Use constant-time operations where appropriate
- Clear sensitive data from memory

## Code Review Process

1. Maintainers will review your PR
2. Address any feedback
3. Once approved, changes will be merged

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
