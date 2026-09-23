# Coding Guidelines and Instructions for Agents

When making modifications to this repository, please adhere to the following strict requirements. Failure to run and pass these checks will result in a Continuous Integration (CI) failure.

**IMPORTANT:** Always use Simplified Chinese (简体中文) when communicating and providing explanations.

## 核心原则 (Core Principles)

1. **回复语言**：始终使用**中文**回复。
2. **代码风格**：
   - **严禁使用 `mod.rs`**。必须遵守 Rust 2018 Edition 及更新版本的目录结构标准。
   - 模块 `foo` 应定义在 `foo.rs` 中；若有子模块，创建 `foo/` 目录，但父模块代码仍保留在 `foo.rs`，而非 `foo/mod.rs`。
3. **禁止猜测**：严禁猜测代码逻辑或文件内容；修改或回答前必须先读取相关代码。
4. **主动报告**：阅读代码时应主动报告潜在错误、安全漏洞、性能问题。
5. **注释风格**: 代码注释始终以中文为主，禁止无意义注释，注释只应当解释相关代码，不应当涉及任何报告、方案。
