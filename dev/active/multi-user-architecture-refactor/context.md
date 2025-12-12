# 任务上下文

**任务名称**: 多用户架构改造
**任务目录**: dev/active/multi-user-architecture-refactor
**需求类型**: REFACTOR（架构重构）
**执行模式**: step（分步模式）
**创建时间**: 2025-12-11T00:00:00Z
**当前阶段**: 1（需求分析）
**任务状态**: 进行中

## 需求描述

把项目从单用户模式改造成多用户模式,支持多个用户登录。

## 项目上下文

**技术栈**:
- 后端：Node.js + TypeScript + Express
- 前端：React + Vite
- 进程管理：ClaudeProcessManager
- 数据库：SQLite (better-sqlite3)
- 测试框架：Vitest

**项目类型**: 现有项目（棕地开发）

**现有模块**:
- CUIServer（主服务器）
- ClaudeProcessManager（进程管理）
- ConversationStatusManager（会话管理）
- PermissionTracker（权限跟踪）
- ConfigService（配置管理）
- authMiddleware（认证中间件）
- StreamManager（流管理）
- SessionInfoService（会话信息服务）

## 需求信息摘要

| 字段 | 内容 |
|-----|------|
| **重构名称** | 多用户架构改造 |
| **重构类型** | 架构升级（单用户→多用户） |
| **重构模块** | 进程管理、会话管理、权限控制、认证 |
| **架构现状** | 单用户模式，单一会话，所有用户共享同一个Claude进程 |
| **目标架构** | 多用户隔离，每用户独立进程，真实用户权限隔离（sudo切换用户） |
| **验证策略** | 单元测试覆盖核心功能，不保留单用户模式 |
| **主要风险** | ①用户隔离不完善导致数据泄露 ②sudo权限配置问题 ③多进程资源消耗过大 ④会话管理混乱 |
| **性能目标** | 大规模部署，目标支持2000用户 |
| **技术方案** | sudo切换用户、目录权限隔离（/mnt/bdap/<username>） |

## 阶段完成情况

- [x] 阶段-1: 项目上下文分析 ✅
- [x] 阶段0: 需求澄清 ✅ clarification_result.json (2025-12-11T10:30:00+08:00)
- [ ] 阶段1: 需求分析（当前）
- [ ] 阶段2: 设计方案生成
- [ ] 阶段3: 代码开发
- [ ] 阶段4: 测试用例生成

## 推荐Agents

- 阶段0: req-clarification-orchestrator
- 阶段1: req-refactor-analyzer
- 阶段2: des-refactor
- 阶段3: 根据技术栈自动选择（Node.js/TypeScript）
- 阶段4: regression-test-generator

## 执行日志

- [2025-12-11T00:00:00Z] 开始执行工作流
- [2025-12-11T00:00:00Z] 需求类型识别：REFACTOR（置信度95%）
- [2025-12-11T00:00:00Z] 用户选择：分步模式
- [2025-12-11T00:00:00Z] 任务工作区创建完成
- [2025-12-11T10:10:00+08:00] 阶段0开始：需求澄清对话（2轮）
- [2025-12-11T10:30:00+08:00] 阶段0完成：澄清结果已生成

## 已生成产物

- clarification_result.json: dev/active/multi-user-architecture-refactor/clarification_result.json
