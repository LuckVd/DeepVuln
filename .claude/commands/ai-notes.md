---
description: Read or append to the AI notes from docs/ai-notes.md.
---

Read or append to the AI notes from docs/ai-notes.md.

Respond in Chinese for all user-facing natural language output. Keep commands, file paths, and code identifiers in their original form.

Requirements:

**模式 1: 读取（无参数）**
1. Read the content of docs/ai-notes.md
2. Display the full content to the user
3. If the file doesn't exist, inform the user

**模式 2: 新增内容（带参数）**
1. Check if docs/ai-notes.md exists, create if not
2. Read the current content first
3. Append the new content provided by the user
4. Format the new entry with date stamp (YYYY-MM-DD)
5. Update the file using Write tool (must read first)

新增内容格式：
```markdown
## YYYY-MM-DD - [简短标题]

[用户输入的内容]

---
```

Usage examples:
- `/ai-notes` - 读取所有笔记
- `/ai-notes 网络代理配置变更` - 添加新条目
- `/ai-notes 注意：端口 8080 被 Java 服务占用` - 添加新条目
