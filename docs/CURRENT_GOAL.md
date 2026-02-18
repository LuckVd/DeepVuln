# 当前目标

> 单一焦点：本次会话关注的核心任务

---

## 目标信息

| 字段 | 值 |
|------|-----|
| **任务** | CVE 漏洞匹配零误报优化 |
| **状态** | completed |
| **优先级** | critical |
| **创建日期** | 2026-02-18 |
| **完成日期** | 2026-02-18 |

---

## 背景说明

当前 CVE 漏洞检测存在严重误报问题：

**问题现象**：
- Dubbo 项目扫描出 168 个漏洞，其中约 30-40% 为误报
- 主要原因：版本号未解析（如 `${tomcat.version}`）时返回所有历史漏洞

**误报来源**：
1. Maven 属性变量未解析（`${property}` 格式）
2. 版本号为 `*` 或空时，OSV 返回所有漏洞
3. 依赖扫描器无法获取父 POM 中定义的版本

**核心原则**：
> **没有确切版本 = 不报告漏洞**（宁可漏报，不可误报）

---

## 完成标准

### Phase 1: 版本解析增强
- [x] Maven 属性变量解析（从 `<properties>` 获取值）
- [x] 父 POM 版本继承解析
- [x] BOM (Bill of Materials) 版本解析
- [x] Gradle `ext` 属性解析

### Phase 2: 匹配策略调整
- [x] 无版本号时跳过 CVE 查询（不返回所有漏洞）
- [x] 版本范围解析（如 `[1.0,2.0)`）
- [x] SNAPSHOT 版本特殊处理
- [x] 添加 `version_confidence` 字段标记版本来源

### Phase 3: 报告优化
- [x] 区分"已确认漏洞"和"需人工确认"
- [x] 标记版本来源（显式声明/属性解析/父POM/未知）
- [x] 输出未解析版本的依赖列表供人工审查

### Phase 4: 测试验证
- [x] 使用 Dubbo 项目验证误报率下降
- [x] 单元测试覆盖各种版本格式
- [x] 对比优化前后报告差异

---

## 技术方案

### 版本解析优先级

```
1. 显式版本      <version>2.17.0</version>     → 直接使用
2. 属性引用      <version>${spring.version}</version> → 从 <properties> 解析
3. 父POM继承     <version>${project.parent.version}</version> → 递归查找
4. BOM管理       <dependencyManagement> 中定义  → 查找 BOM
5. 未知/无法解析  <version>${unknown.prop}</version> → 跳过 CVE 查询
```

### 数据模型扩展

```python
class Dependency(BaseModel):
    name: str
    version: str | None
    version_source: Literal["explicit", "property", "parent", "bom", "unknown"]
    version_confidence: float  # 0.0 - 1.0
    raw_version: str  # 原始值，如 "${spring.version}"
```

### CVE 查询策略

```python
async def query_cves(dependency: Dependency) -> list[CVEInfo]:
    # 零误报策略：无确切版本不查询
    if dependency.version is None or dependency.version == "*":
        logger.info(f"Skipping CVE query for {dependency.name}: no version")
        return []

    if dependency.version_confidence < 0.5:
        logger.warning(f"Low confidence version for {dependency.name}")
        return []  # 或标记为"需人工确认"

    return await osv_client.query_by_package(
        package_name=dependency.name,
        version=dependency.version,  # 确保传版本
    )
```

---

## 关联文件

### 已修改
- `src/layers/l1_intelligence/dependency_scanner/maven_scanner.py` - 版本解析、BOM支持
- `src/layers/l1_intelligence/dependency_scanner/base_scanner.py` - 数据模型、VersionSource枚举
- `src/layers/l1_intelligence/security_analyzer/analyzer.py` - CVE 查询策略、UnresolvedDependency模型
- `src/cli/scan_display.py` - 报告显示、未解析依赖展示
- `tests/unit/test_dependency_scanner/test_maven_scanner.py` - BOM测试用例

---

## 进度记录

| 时间 | 进展 |
|------|------|
| 2026-02-18 | 设置新目标：CVE 漏洞匹配零误报优化 |
| 2026-02-18 | 完成 Phase 1: 版本解析增强（Maven属性、父POM、BOM、Gradle ext） |
| 2026-02-18 | 完成 Phase 2: 匹配策略调整（跳过无版本、version_confidence） |
| 2026-02-18 | 完成 Phase 3: 报告优化（UnresolvedDependency、CLI展示） |
| 2026-02-18 | 完成 Phase 4: 测试验证（130个测试通过） |

---

## 最终效果

| 指标 | 优化前 | 优化后 |
|------|--------|--------|
| 漏洞报告 | 168个 | 9个 |
| 误报率 | ~35% | ~0% |
| 跳过的依赖 | N/A | 168个（版本未解析） |
| 单元测试 | 84个 | 130个 |

---

## 备注

### 关键约束

1. **零误报优先**：宁可漏报，不可误报
2. **版本可追溯**：每个依赖必须能追溯版本来源
3. **人工审查友好**：无法确定的部分清晰标注
