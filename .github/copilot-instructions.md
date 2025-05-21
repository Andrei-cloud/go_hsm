# Copilot Instructions

## Coding Rules:
* All comments must end in a period.  
* `return` and `continue` should have an empty line before.  
* No extra empty line at the start of a block.  
* Maximum line length is 100 characters.  
* Use tabs for indentation, not spaces.  
* Use camelCase for variable and function names.  
* Use PascalCase for exported functions, types, and variables.  
* Add a space after keywords like `if`, `for`, `switch`.  
* Always use braces for control structures, even for single-line bodies.  
* Declaration order: `const`, `var`, `type`, then `func`.  
* Group related constants and variables together.  
* Order struct fields by size (largest to smallest) to minimize padding.  
* For imports, group standard library, third-party, and local packages with a blank line between groups.  
* `type` declarations must not come after functions.  
* error strings should not be capitalized or end with punctuation or a newline.  
* Always check error returns.  
* Return errors rather than using panics for expected error conditions.  
* Use custom error types when additional context is valuable.  
* Replace `interface{}` with `any` when possible (Go 1.18+).  
* Use generics for type-safe code when appropriate (Go 1.18+).  
* Use `context.Context` as the first parameter for functions that may block.  
* Prefer `time.Time` over integer timestamps.  
* Use structured logging with fields instead of string formatting.  
* Every package should have a corresponding `*_test.go` file.  
* Use table-driven tests for multiple test cases.  
* Test file names should match the file they test with `_test.go` suffix.  
* Test function names should follow `Test<FunctionName><Scenario>` pattern.  
* Every exported type, function, method, and package needs documentation.  
* Include examples in documentation when behavior might not be obvious.  
* Package documentation should be in a file named `doc.go`.
