# API Documentation

> 项目 API 契约文档

---

## 生命周期状态

| 状态 | 说明 | Breaking Change |
|------|------|-----------------|
| `experimental` | 实验阶段 | 允许 |
| `stable` | 稳定阶段 | 禁止（需版本升级） |
| `deprecated` | 废弃阶段 | 仅允许删除 |

---

## 接口必备字段

| 字段 | 必须 | 说明 |
|------|------|------|
| Endpoint | 是 | 例如 `GET /users/{id}` |
| Method | 是 | HTTP 方法 |
| Summary | 是 | 简要说明 |
| Status | 是 | 生命周期状态 |
| Auth | 建议 | required / optional / none |

---

## Breaking Change 判定

对于 `stable` 状态的 API，以下视为 Breaking Change：

- 删除字段
- 修改字段类型
- 修改 required 属性
- 修改响应结构导致不兼容

**允许的操作：**
- 新增可选字段
- 新增不冲突的新接口

---

## API 列表

> 项目实际 API 定义

（待项目开发后填充）

---

## 示例格式

```markdown
### GET /users/{id}

- **Summary**: 获取用户信息
- **Status**: stable
- **Auth**: required

**Parameters:**
| name | in | type | required |
|------|-----|------|----------|
| id | path | string | true |

**Response:**
```json
{
  "id": "string",
  "name": "string",
  "email": "string"
}
```
```
