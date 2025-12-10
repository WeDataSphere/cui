# CUI 多用户企业版改造方案

> 版本: 1.0
> 日期: 2025-12-10
> 目标: 将 CUI 从单用户应用改造为支持 2000 人规模的企业内部多用户系统

## 目录

- [1. 架构概述](#1-架构概述)
- [2. 核心设计原则](#2-核心设计原则)
- [3. 用户目录隔离方案](#3-用户目录隔离方案)
- [4. 数据库设计](#4-数据库设计)
- [5. 认证系统](#5-认证系统)
- [6. 核心服务改造](#6-核心服务改造)
- [7. API 接口设计](#7-api-接口设计)
- [8. 安全加固措施](#8-安全加固措施)
- [9. 部署方案](#9-部署方案)
- [10. 实施计划](#10-实施计划)

---

## 1. 架构概述

### 1.1 架构图

```
┌─────────────────────────────────────────────────────┐
│         企业统一网关（外部系统）                                  │
│  - 用户登录认证                                      │
│  - 权限控制                                          │
│  - 注入静态 Token (Header: X-Gateway-Token)         │
│  - 注入用户名 Cookie (dss_user_name)                │
│                                                      │
│         运维工具管理用户目录 （外部系统）                          │
└────────────────┬────────────────────────────────────┘
                 │
                 │ 每次请求携带:
                 │ - Header: X-Gateway-Token (静态 token)
                 │ - Cookie: dss_user_name (用户名)
                 ↓
┌─────────────────────────────────────────────────────┐
│            CUI Server (Node.js)                      │
│  ┌───────────────────────────────────────────────┐  │
│  │  认证层（简化）                                 │  │
│  │  - 网关认证中间件                              │  │
│  │    ✅ 验证静态 Token                           │  │
│  │    ✅ 读取用户名 Cookie                        │  │
│  │    ✅ 验证用户目录                             │  │
│  │    ✅ 注入用户上下文                           │  │
│  │                                               │  │
│  │  ❌ 无需 LDAP 集成                             │  │
│  │  ❌ 无需 JWT Token 管理                        │  │
│  │  ❌ 无需登录接口                               │  │
│  └───────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────┐  │
│  │  用户管理层                                    │  │
│  │  - UserMappingService (系统用户映射)          │  │
│  │  - UserService (用户数据库服务)               │  │
│  │  - ConfigService (多用户配置加载)             │  │
│  └───────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────┐  │
│  │  业务逻辑层                                    │  │
│  │  - ClaudeProcessManager (多用户进程管理)      │  │
│  │  - SessionInfoService (会话管理)              │  │
│  │  - HistoryReader (历史记录)                   │  │
│  └───────────────────────────────────────────────┘  │
│  ┌───────────────────────────────────────────────┐  │
│  │  数据持久层                                    │  │
│  │  - MySQL 数据库                               │  │
│  │  - 用户配置表                                  │  │
│  │  - 会话表 (按用户隔离)                        │  │
│  └───────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
                 │
                 ↓ 启动 Claude CLI
┌─────────────────────────────────────────────────────┐
│          用户目录 (由运维工具维护)                     │
│                                                      │
│  /home/zhangsan/                                     │
│    ├── .claude/          # Claude CLI 配置和历史     │
│    ├── .cui/             # CUI 用户配置              │
│    │   └── config.json   # 用户专属配置              │
│    └── workspace/        # 用户工作区                │
│                                                      │
│  /home/lisi/                                         │
│    ├── .claude/                                      │
│    ├── .cui/                                         │
│    └── workspace/                                    │
└─────────────────────────────────────────────────────┘
```

### 1.2 职责划分

| 层级 | 职责 | 负责方 |
|------|------|--------|
| **运维层（外部系统）** | 用户账号创建、目录初始化、权限设置 | 运维团队 + 运维工具 |
| **网关层（外部系统）** | 用户身份认证、权限控制、Token/Cookie 注入 | 企业统一网关 |
| **认证层** | 验证网关 Token、读取用户信息、注入上下文 | CUI 应用 |
| **应用层** | 业务逻辑、Claude CLI 管理 | CUI 应用 |
| **数据层** | 用户配置、会话数据持久化 | CUI 应用 + MySQL |

---

## 2. 核心设计原则

### 2.1 用户目录管理

- ✅ **运维工具负责**：用户目录的创建、删除、权限设置
- ✅ **CUI 应用负责**：读取和使用现有用户目录
- ❌ **CUI 不负责**：创建用户目录、修改文件权限

### 2.2 认证方式

- ✅ **网关统一认证**：企业统一网关完成用户登录和认证
- ✅ **静态 Token 验证**：验证请求来自可信网关（Header: `X-Gateway-Token`）
- ✅ **Cookie 传递用户**：从 Cookie 读取用户名（`dss_user_name`）
- ❌ **无需 LDAP 集成**：网关已完成认证，CUI 无需对接 LDAP
- ❌ **无需 JWT Token**：网关已管理会话，CUI 无需 JWT
- ❌ **无需登录接口**：用户在网关层登录，CUI 无需登录页面

### 2.3 隔离原则

- ✅ **文件系统隔离**：每个用户独立的 HOME 目录
- ✅ **进程隔离**：每个 Claude CLI 进程使用用户专属环境变量
- ✅ **数据隔离**：数据库按 user_id 隔离
- ✅ **配置隔离**：每个用户独立的 .cui/config.json

### 2.4 安全原则

- ✅ 文件系统权限严格控制（700）
- ✅ 所有 API 必须经过认证
- ✅ 审计日志记录关键操作

---

## 3. 用户目录隔离方案

### 3.1 目录结构设计

```bash
/home/
├── zhangsan/                    # 用户 zhangsan 的 HOME 目录
│   ├── .claude/                 # Claude CLI 配置和历史
│   │   ├── config.json          # Claude CLI 配置
│   │   └── projects/            # Claude 项目历史
│   │       └── xxx.jsonl        # 会话历史记录
│   ├── .cui/                    # CUI 用户配置目录
│   │   ├── config.json          # CUI 用户配置（可选）
│   │   └── session-info.db      # 会话信息数据库（可选）
│   └── workspace/               # 用户工作区
│       └── project1/            # 用户项目
│
├── lisi/
│   ├── .claude/
│   ├── .cui/
│   └── workspace/
│
└── wangwu/
    ├── .claude/
    ├── .cui/
    └── workspace/
```

### 3.2 文件权限要求

```bash
# 用户 HOME 目录权限
drwx------ (700)  /home/zhangsan/
drwx------ (700)  /home/zhangsan/.claude/
drwx------ (700)  /home/zhangsan/.cui/
drwx------ (700)  /home/zhangsan/workspace/

# 配置文件权限
-rw------- (600)  /home/zhangsan/.cui/config.json

# 所有者
chown cui-service:cui-service /home/zhangsan/ -R
```

**说明**：
- CUI 服务以 `cui-service` 系统用户运行
- 所有用户目录归 `cui-service` 所有
- 通过目录隔离而非 Linux 用户隔离（简化部署）

---

## 4. 数据库设计

### 4.1 技术选型

- **数据库**：MySQL 8.0 或 PostgreSQL 15
- **推荐**：PostgreSQL（更好的 JSON 支持，用于存储会话历史）

### 4.2 数据库 Schema

```sql
-- ============================================
-- 用户表（存储用户基本信息和配置）
-- ============================================
CREATE TABLE users (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  username VARCHAR(100) UNIQUE NOT NULL COMMENT '用户名（对应系统用户名）',
  email VARCHAR(255) COMMENT '邮箱',
  display_name VARCHAR(100) COMMENT '显示名称',
  home_directory VARCHAR(255) NOT NULL COMMENT '用户 HOME 目录路径',

  -- 用户偏好设置（与 Claude CLI 无关的配置）
  preferences JSON COMMENT '用户偏好配置，如：{"theme":"dark","notifications":true}',

  -- 功能开关
  feature_flags JSON COMMENT '功能开关，如：{"enable_gemini":true,"enable_router":false}',

  -- 配额管理
  quota_limit INT DEFAULT 1000 COMMENT '每月对话配额',
  quota_used INT DEFAULT 0 COMMENT '本月已使用配额',
  quota_reset_at TIMESTAMP COMMENT '配额重置时间',

  -- 状态
  status ENUM('active', 'disabled', 'suspended') DEFAULT 'active' COMMENT '用户状态',

  -- 时间戳
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP COMMENT '最后登录时间',

  -- 索引
  INDEX idx_username (username),
  INDEX idx_status (status),
  INDEX idx_created_at (created_at)
) COMMENT='用户表';

-- ============================================
-- 会话表（添加 user_id 字段）
-- ============================================
CREATE TABLE sessions (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL COMMENT '所属用户 ID',
  session_id VARCHAR(255) UNIQUE NOT NULL COMMENT 'Claude 会话 ID',
  custom_name VARCHAR(255) DEFAULT '' COMMENT '自定义会话名称',

  -- 会话状态
  status ENUM('active', 'completed', 'failed') DEFAULT 'active',

  -- 会话元数据
  project_path VARCHAR(500) COMMENT '项目路径',
  model VARCHAR(50) COMMENT '使用的模型',
  total_duration INT DEFAULT 0 COMMENT '总耗时（毫秒）',

  -- 会话统计
  message_count INT DEFAULT 0 COMMENT '消息数量',
  token_count INT DEFAULT 0 COMMENT 'Token 消耗',

  -- 会话标签
  pinned BOOLEAN DEFAULT FALSE COMMENT '是否置顶',
  archived BOOLEAN DEFAULT FALSE COMMENT '是否归档',

  -- 时间戳
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  -- 外键和索引
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_sessions (user_id, created_at DESC),
  INDEX idx_session_id (session_id),
  INDEX idx_status (user_id, status)
) COMMENT='会话表';

-- ============================================
-- Web Push 订阅表（添加 user_id 字段）
-- ============================================
CREATE TABLE subscriptions (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT NOT NULL COMMENT '所属用户 ID',
  endpoint TEXT NOT NULL COMMENT 'Push 订阅端点',
  p256dh TEXT NOT NULL COMMENT 'P256DH 密钥',
  auth TEXT NOT NULL COMMENT 'Auth 密钥',
  user_agent VARCHAR(500) DEFAULT '' COMMENT '用户代理',

  -- 状态
  expired BOOLEAN DEFAULT FALSE COMMENT '是否过期',

  -- 时间戳
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP COMMENT '最后活跃时间',

  -- 外键和索引
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  INDEX idx_user_subscriptions (user_id),
  INDEX idx_expired (expired)
) COMMENT='Web Push 订阅表';

-- ============================================
-- 审计日志表（可选）
-- ============================================
CREATE TABLE audit_logs (
  id BIGINT PRIMARY KEY AUTO_INCREMENT,
  user_id BIGINT COMMENT '操作用户 ID',
  username VARCHAR(100) COMMENT '用户名',

  -- 操作信息
  action VARCHAR(100) NOT NULL COMMENT '操作类型，如：start_conversation, execute_bash',
  resource_type VARCHAR(50) COMMENT '资源类型，如：conversation, file',
  resource_id VARCHAR(255) COMMENT '资源 ID',

  -- 操作详情
  details JSON COMMENT '操作详情',

  -- 请求信息
  ip_address VARCHAR(45) COMMENT 'IP 地址',
  user_agent VARCHAR(500) COMMENT '用户代理',

  -- 结果
  status ENUM('success', 'failure') COMMENT '操作结果',
  error_message TEXT COMMENT '错误信息（如果失败）',

  -- 时间戳
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

  -- 索引
  INDEX idx_user_logs (user_id, created_at DESC),
  INDEX idx_action (action, created_at DESC),
  INDEX idx_created_at (created_at)
) COMMENT='审计日志表';
```

### 4.3 初始化脚本

```sql
-- scripts/init-mysql-database.sql

-- 创建数据库
CREATE DATABASE IF NOT EXISTS cui_db
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE cui_db;

-- 创建表（使用上面的 SQL）
-- ... [上面的建表语句]

-- 创建示例用户
INSERT INTO users (username, email, display_name, home_directory, status, preferences, feature_flags)
VALUES
  ('zhangsan', 'zhangsan@company.com', '张三', '/home/zhangsan', 'active',
   '{"theme":"dark","notifications":true}',
   '{"enable_gemini":true,"enable_router":false}'),
  ('lisi', 'lisi@company.com', '李四', '/home/lisi', 'active',
   '{"theme":"light","notifications":false}',
   '{"enable_gemini":false,"enable_router":true}');
```

---

## 5. 认证系统（网关统一认证）

### 5.1 认证流程

```
用户访问 CUI
   ↓
[企业统一网关(外部系统)]
   ↓
网关验证用户登录（LDAP/AD 等）
   ↓
成功 → 注入静态 Token 和用户名 Cookie
   ↓
请求转发到 CUI Server
   ↓
[Header: X-Gateway-Token]
[Cookie: dss_user_name=zhangsan]
   ↓
CUI 网关认证中间件
   ↓
1. 验证静态 Token（确认来自可信网关）
2. 读取用户名 Cookie
3. 验证用户目录存在
4. 注入 req.user 上下文
   ↓
业务逻辑处理
```

### 5.2 网关认证中间件实现（简化）

```typescript
// src/middleware/gateway-auth.ts

import { Request, Response, NextFunction } from 'express';
import { UserMappingService } from '@/services/user-mapping-service.js';
import { createLogger } from '@/services/logger.js';

const logger = createLogger('GatewayAuthMiddleware');
const userMappingService = UserMappingService.getInstance();

// 扩展 Express Request 类型
declare global {
  namespace Express {
    interface Request {
      user?: {
        username: string;
        homeDir: string;
        workspaceDir: string;
        claudeDir: string;
        cuiDir: string;
      };
    }
  }
}

/**
 * 网关认证中间件（简化版）
 *
 * 假设：
 * 1. 请求已通过企业网关认证
 * 2. 请求包含静态 Token（Header: X-Gateway-Token）
 * 3. 请求包含用户名 Cookie（dss_user_name）
 */
export async function gatewayAuthMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    // 跳过测试环境（可选）
    if (process.env.NODE_ENV === 'test' && !process.env.ENABLE_AUTH_IN_TESTS) {
      next();
      return;
    }

    // 1. 验证静态 Token（确认请求来自可信网关）
    const gatewayToken = req.headers['x-gateway-token'] as string;
    const expectedToken = process.env.GATEWAY_TOKEN || 'your-static-gateway-token';

    if (!gatewayToken || gatewayToken !== expectedToken) {
      logger.warn('Invalid or missing gateway token', {
        hasToken: !!gatewayToken,
        ip: req.ip
      });
      res.status(401).json({ error: 'Unauthorized: Invalid gateway token' });
      return;
    }

    // 2. 读取用户名 Cookie
    const username = req.cookies?.dss_user_name;

    if (!username) {
      logger.warn('Missing dss_user_name cookie', { ip: req.ip });
      res.status(401).json({ error: 'Unauthorized: Missing user information' });
      return;
    }

    // 3. 验证用户名格式（防止路径注入攻击）
    if (!isValidUsername(username)) {
      logger.warn('Invalid username format', { username, ip: req.ip });
      res.status(400).json({ error: 'Invalid username format' });
      return;
    }

    // 4. 获取用户目录映射（验证用户存在且目录可访问）
    const mapping = await userMappingService.getUserMapping(username);
    if (!mapping) {
      logger.error('User not found or directory not accessible', {
        username,
        ip: req.ip
      });
      res.status(403).json({ error: 'User not configured or directory not accessible' });
      return;
    }

    // 5. 注入用户上下文到 request
    req.user = {
      username: mapping.username,
      homeDir: mapping.homeDir,
      workspaceDir: mapping.workspaceDir,
      claudeDir: mapping.claudeDir,
      cuiDir: mapping.cuiDir,
    };

    logger.debug('Gateway authentication successful', {
      username,
      homeDir: mapping.homeDir
    });

    next();
  } catch (error) {
    logger.error('Gateway authentication error', { error });
    res.status(500).json({ error: 'Internal server error' });
  }
}

/**
 * 验证用户名格式（防止路径注入）
 */
function isValidUsername(username: string): boolean {
  // 只允许字母、数字、下划线、中划线
  const regex = /^[a-zA-Z0-9_-]+$/;

  // 长度限制
  if (username.length < 1 || username.length > 50) {
    return false;
  }

  // 不允许路径遍历字符
  if (username.includes('/') || username.includes('\\') || username.includes('..')) {
    return false;
  }

  return regex.test(username);
}
```

### 5.3 配置和使用

#### 环境变量配置

```bash
# .env.production

# 网关静态 Token（与网关约定的密钥）
GATEWAY_TOKEN=your-secure-static-token-here

# 其他配置...
```

#### 在 CUI Server 中使用

```typescript
// src/cui-server.ts

import express from 'express';
import cookieParser from 'cookie-parser';
import { gatewayAuthMiddleware } from './middleware/gateway-auth.js';

const app = express();

// 1. 必须：解析 Cookie（用于读取 dss_user_name）
app.use(cookieParser());

// 2. 其他中间件
app.use(express.json());

// 3. 应用网关认证中间件到所有 API 路由
app.use('/api', gatewayAuthMiddleware);

// 4. 业务路由
app.use('/api/conversations', conversationRoutes);
app.use('/api/users', userRoutes);

// 健康检查等公开接口不需要认证
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});
```
ß
---

## 6. 核心服务改造

### 6.1 UserMappingService（用户目录映射）

```typescript
// src/services/user-mapping-service.ts

import { exec } from 'child_process';
import { promisify } from 'util';
import fs from 'fs/promises';
import path from 'path';
import { createLogger } from './logger.js';

const execAsync = promisify(exec);

export interface UserMapping {
  username: string;
  homeDir: string;
  workspaceDir: string;
  claudeDir: string;
  cuiDir: string;
}

export class UserMappingService {
  private static instance: UserMappingService;
  private logger = createLogger('UserMappingService');
  private userCache = new Map<string, UserMapping>();
  private cacheExpiry = 5 * 60 * 1000; // 缓存 5 分钟

  static getInstance(): UserMappingService {
    if (!UserMappingService.instance) {
      UserMappingService.instance = new UserMappingService();
    }
    return UserMappingService.instance;
  }

  /**
   * 根据用户名获取用户目录映射
   * 直接读取系统用户信息
   */
  async getUserMapping(username: string): Promise<UserMapping | null> {
    // 检查缓存
    if (this.userCache.has(username)) {
      return this.userCache.get(username)!;
    }

    try {
      // 读取系统用户信息
      const { stdout } = await execAsync(`getent passwd ${username}`);
      const parts = stdout.trim().split(':');

      if (parts.length < 6) {
        this.logger.warn('User not found in system', { username });
        return null;
      }

      const homeDir = parts[5]; // /home/username

      // 验证目录是否存在且可访问
      try {
        await fs.access(homeDir, fs.constants.R_OK | fs.constants.W_OK);
      } catch {
        this.logger.error('User home directory not accessible', { username, homeDir });
        return null;
      }

      // 构建目录映射
      const mapping: UserMapping = {
        username,
        homeDir,
        workspaceDir: path.join(homeDir, 'workspace'),
        claudeDir: path.join(homeDir, '.claude'),
        cuiDir: path.join(homeDir, '.cui'),
      };

      // 验证必要目录存在
      const dirsToCheck = [mapping.claudeDir, mapping.cuiDir, mapping.workspaceDir];
      for (const dir of dirsToCheck) {
        try {
          await fs.access(dir, fs.constants.R_OK | fs.constants.W_OK);
        } catch {
          this.logger.warn('Required directory not found', {
            username,
            dir,
            note: 'Directory should be created by ops team'
          });
        }
      }

      // 缓存映射
      this.userCache.set(username, mapping);

      // 设置缓存过期（5分钟后清除）
      setTimeout(() => {
        this.userCache.delete(username);
      }, this.cacheExpiry);

      this.logger.info('User mapping loaded', {
        username,
        homeDir,
        workspaceDir: mapping.workspaceDir
      });

      return mapping;
    } catch (error) {
      this.logger.error('Failed to get user mapping', { username, error });
      return null;
    }
  }

  /**
   * 验证用户是否存在且目录可用
   */
  async validateUser(username: string): Promise<boolean> {
    const mapping = await this.getUserMapping(username);
    return mapping !== null;
  }

  /**
   * 清除缓存（用于用户更新时）
   */
  clearCache(username?: string): void {
    if (username) {
      this.userCache.delete(username);
      this.logger.debug('User mapping cache cleared', { username });
    } else {
      this.userCache.clear();
      this.logger.debug('All user mapping cache cleared');
    }
  }
}
```

### 6.2 ConfigService 改造（多用户配置）

```typescript
// src/services/config-service.ts

import fs from 'fs';
import path from 'path';
import { CUIConfig, DEFAULT_CONFIG } from '@/types/config.js';
import { createLogger, type Logger } from './logger.js';

/**
 * ConfigService 多用户版本
 * 支持加载每个用户的独立配置
 */
export class ConfigService {
  private static instance: ConfigService;
  private configs: Map<string, CUIConfig> = new Map();
  private logger: Logger;
  private serverConfig: CUIConfig | null = null;

  private constructor() {
    this.logger = createLogger('ConfigService');
  }

  static getInstance(): ConfigService {
    if (!ConfigService.instance) {
      ConfigService.instance = new ConfigService();
    }
    return ConfigService.instance;
  }

  /**
   * 初始化服务器全局配置（可选）
   */
  async initialize(): Promise<void> {
    const serverConfigPath = process.env.CUI_SERVER_CONFIG || '/etc/cui/server-config.json';

    try {
      if (fs.existsSync(serverConfigPath)) {
        const configData = fs.readFileSync(serverConfigPath, 'utf-8');
        this.serverConfig = JSON.parse(configData);
        this.logger.info('Server config loaded', { configPath: serverConfigPath });
      } else {
        this.serverConfig = DEFAULT_CONFIG;
        this.logger.info('Using default server config');
      }
    } catch (error) {
      this.logger.error('Failed to load server config', { error });
      this.serverConfig = DEFAULT_CONFIG;
    }
  }

  /**
   * 加载用户配置
   * @param username 用户名
   * @param userCuiDir 用户的 .cui 目录路径
   */
  async loadUserConfig(username: string, userCuiDir: string): Promise<CUIConfig> {
    // 检查缓存
    if (this.configs.has(username)) {
      return this.configs.get(username)!;
    }

    const configPath = path.join(userCuiDir, 'config.json');

    try {
      let config: CUIConfig;

      if (!fs.existsSync(configPath)) {
        // 配置文件不存在，使用默认配置
        this.logger.warn('User config not found, using defaults', {
          username,
          configPath
        });

        config = {
          ...DEFAULT_CONFIG,
          machine_id: `user_${username}`,
          authToken: '', // 不使用用户级别的 authToken
        };
      } else {
        // 读取配置文件
        const configData = fs.readFileSync(configPath, 'utf-8');
        const userConfig = JSON.parse(configData);

        // 合并默认配置
        config = {
          ...DEFAULT_CONFIG,
          ...userConfig,
          server: { ...DEFAULT_CONFIG.server, ...(userConfig.server || {}) },
          interface: { ...DEFAULT_CONFIG.interface, ...(userConfig.interface || {}) }
        };

        this.logger.info('User config loaded', { username, configPath });
      }

      // 缓存配置
      this.configs.set(username, config);
      return config;
    } catch (error) {
      this.logger.error('Failed to load user config', { username, configPath, error });

      // 返回默认配置
      const defaultConfig: CUIConfig = {
        ...DEFAULT_CONFIG,
        machine_id: `user_${username}`,
        authToken: '',
      };

      this.configs.set(username, defaultConfig);
      return defaultConfig;
    }
  }

  /**
   * 获取用户配置（必须先调用 loadUserConfig）
   */
  getUserConfig(username: string): CUIConfig {
    const config = this.configs.get(username);
    if (!config) {
      throw new Error(`User config not loaded for ${username}. Call loadUserConfig first.`);
    }
    return config;
  }

  /**
   * 获取服务器全局配置
   */
  getConfig(): CUIConfig {
    if (!this.serverConfig) {
      throw new Error('Server configuration not initialized. Call initialize() first.');
    }
    return this.serverConfig;
  }

  /**
   * 清除用户配置缓存
   */
  clearUserCache(username?: string): void {
    if (username) {
      this.configs.delete(username);
      this.logger.debug('User config cache cleared', { username });
    } else {
      this.configs.clear();
      this.logger.debug('All user config cache cleared');
    }
  }

  /**
   * 重置单例（用于测试）
   */
  static resetInstance(): void {
    ConfigService.instance = null as any;
  }
}
```

### 6.3 ClaudeProcessManager 改造

```typescript
// src/services/claude-process-manager.ts

import { ChildProcess, spawn } from 'child_process';
import { ConversationConfig } from '@/types/index.js';
import { createLogger, type Logger } from './logger.js';
import path from 'path';

// 扩展 ConversationConfig 类型
interface MultiUserConversationConfig extends ConversationConfig {
  userContext: {
    username: string;
    homeDir: string;
    workspaceDir: string;
    claudeDir: string;
    cuiDir: string;
  };
}

export class ClaudeProcessManager {
  private logger: Logger;
  private claudeExecutablePath: string;
  // ... 其他字段

  constructor(/* ... 现有参数 */) {
    this.logger = createLogger('ClaudeProcessManager');
    this.claudeExecutablePath = this.findClaudeExecutable();
    // ... 其他初始化
  }

  /**
   * 启动 Claude CLI 进程（多用户版本）
   */
  private startClaudeProcess(config: MultiUserConversationConfig): ChildProcess {
    const { userContext } = config;

    // ⭐ 关键：为每个用户设置独立的环境变量
    const env = {
      ...process.env,

      // 用户专属环境变量
      HOME: userContext.homeDir,           // 用户 HOME 目录
      CLAUDE_HOME: userContext.claudeDir,   // Claude 配置目录
      USER: userContext.username,           // 用户名
      LOGNAME: userContext.username,        // 登录名

      // CUI 配置目录
      CUI_CONFIG_DIR: userContext.cuiDir,

      // 其他环境变量
      SHELL: '/bin/bash',
    };

    const args = [
      '--cwd', userContext.workspaceDir,
      // ... 其他 Claude CLI 参数
    ];

    this.logger.info('Starting Claude CLI for user', {
      username: userContext.username,
      home: userContext.homeDir,
      workspace: userContext.workspaceDir,
      claudeHome: userContext.claudeDir,
    });

    // 可选：使用 firejail 沙箱
    const useSandbox = process.env.USE_FIREJAIL === 'true';

    let command: string;
    let spawnArgs: string[];

    if (useSandbox) {
      command = 'firejail';
      spawnArgs = [
        '--noprofile',
        '--private=' + userContext.homeDir,  // 私有 HOME 目录
        '--private-tmp',                      // 私有 /tmp
        '--noroot',                           // 禁止 root
        '--',
        this.claudeExecutablePath,
        ...args
      ];
      this.logger.debug('Using firejail sandbox');
    } else {
      command = this.claudeExecutablePath;
      spawnArgs = args;
    }

    const claudeProcess = spawn(command, spawnArgs, {
      cwd: userContext.workspaceDir,  // 工作目录
      env: env,                        // 环境变量
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: false,
    });

    // 记录进程 PID
    this.logger.debug('Claude CLI process started', {
      username: userContext.username,
      pid: claudeProcess.pid,
    });

    return claudeProcess;
  }

  /**
   * 启动对话（公共接口）
   */
  async startConversation(config: MultiUserConversationConfig): Promise<{ sessionId: string }> {
    // 验证用户上下文
    if (!config.userContext || !config.userContext.username) {
      throw new Error('User context is required');
    }

    // 启动进程
    const process = this.startClaudeProcess(config);

    // ... 其他逻辑（进程管理、事件监听等）

    return { sessionId: 'generated-session-id' };
  }

  // ... 其他方法
}
```

### 6.4 UserService（用户数据库服务）

```typescript
// src/services/user-service.ts

import Database from 'mysql2/promise';
import { createLogger } from './logger.js';

export interface User {
  id: string;
  username: string;
  email: string;
  display_name: string;
  home_directory: string;
  preferences: Record<string, any>;
  feature_flags: Record<string, boolean>;
  quota_limit: number;
  quota_used: number;
  status: 'active' | 'disabled' | 'suspended';
  last_login_at: Date | null;
}

export class UserService {
  private static instance: UserService;
  private db!: Database.Connection;
  private logger = createLogger('UserService');

  static getInstance(): UserService {
    if (!UserService.instance) {
      UserService.instance = new UserService();
    }
    return UserService.instance;
  }

  /**
   * 初始化数据库连接
   */
  async initialize(): Promise<void> {
    this.db = await Database.createConnection({
      host: process.env.DB_HOST || 'localhost',
      port: parseInt(process.env.DB_PORT || '3306'),
      user: process.env.DB_USER || 'cui',
      password: process.env.DB_PASSWORD || 'password',
      database: process.env.DB_NAME || 'cui_db',
    });

    this.logger.info('UserService initialized');
  }

  /**
   * 通过用户名获取用户
   */
  async getUserByUsername(username: string): Promise<User | null> {
    const [rows] = await this.db.execute(
      `SELECT id, username, email, display_name, home_directory,
              preferences, feature_flags, quota_limit, quota_used,
              status, last_login_at
       FROM users
       WHERE username = ? AND status = 'active'`,
      [username]
    );

    const users = rows as any[];
    if (users.length === 0) {
      return null;
    }

    const user = users[0];
    return {
      id: user.id.toString(),
      username: user.username,
      email: user.email,
      display_name: user.display_name,
      home_directory: user.home_directory,
      preferences: JSON.parse(user.preferences || '{}'),
      feature_flags: JSON.parse(user.feature_flags || '{}'),
      quota_limit: user.quota_limit,
      quota_used: user.quota_used,
      status: user.status,
      last_login_at: user.last_login_at,
    };
  }

  /**
   * 更新最后登录时间
   */
  async updateLastLogin(username: string): Promise<void> {
    await this.db.execute(
      'UPDATE users SET last_login_at = NOW() WHERE username = ?',
      [username]
    );
  }

  /**
   * 更新用户偏好设置
   */
  async updatePreferences(username: string, preferences: Record<string, any>): Promise<void> {
    await this.db.execute(
      'UPDATE users SET preferences = ? WHERE username = ?',
      [JSON.stringify(preferences), username]
    );

    this.logger.info('User preferences updated', { username });
  }

  /**
   * 更新功能开关
   */
  async updateFeatureFlags(username: string, flags: Record<string, boolean>): Promise<void> {
    await this.db.execute(
      'UPDATE users SET feature_flags = ? WHERE username = ?',
      [JSON.stringify(flags), username]
    );

    this.logger.info('User feature flags updated', { username });
  }

  /**
   * 增加配额使用量
   */
  async incrementQuotaUsage(username: string, amount: number = 1): Promise<void> {
    await this.db.execute(
      'UPDATE users SET quota_used = quota_used + ? WHERE username = ?',
      [amount, username]
    );
  }

  /**
   * 检查用户配额
   */
  async checkQuota(username: string): Promise<{ hasQuota: boolean; remaining: number }> {
    const user = await this.getUserByUsername(username);
    if (!user) {
      return { hasQuota: false, remaining: 0 };
    }

    const remaining = user.quota_limit - user.quota_used;
    return {
      hasQuota: remaining > 0,
      remaining: Math.max(0, remaining),
    };
  }
}
```

---

## 7. API 接口设计

### 7.1 认证说明

**所有 API 请求都通过企业网关认证**，必须携带：
- Header: `X-Gateway-Token: <static-token>`
- Cookie: `dss_user_name=<username>`

CUI 不再提供登录相关 API，用户在网关层完成登录。

### 7.2 用户相关

```typescript
// GET /api/users/me
// 获取当前用户信息
Request Headers:
X-Gateway-Token: <static-token>
Cookie: dss_user_name=zhangsan

Response:
{
  "username": "zhangsan",
  "email": "zhangsan@company.com",
  "displayName": "张三",
  "preferences": {
    "theme": "dark",
    "notifications": true
  },
  "featureFlags": {
    "enable_gemini": true,
    "enable_router": false
  },
  "quota": {
    "limit": 1000,
    "used": 150,
    "remaining": 850
  }
}

// PATCH /api/users/me/preferences
// 更新用户偏好
Request:
{
  "theme": "light",
  "notifications": false
}

Response:
{
  "success": true,
  "preferences": {
    "theme": "light",
    "notifications": false
  }
}
```

### 7.3 对话相关

```typescript
// POST /api/conversations/start
// 启动对话
Request Headers:
X-Gateway-Token: <static-token>
Cookie: dss_user_name=zhangsan

Request Body:
{
  "prompt": "Hello Claude",
  "cwd": "/home/zhangsan/workspace/project1"  // 可选，默认为用户 workspace
}

Response:
{
  "sessionId": "abc123",
  "status": "started"
}

// 其他对话相关接口保持不变，但都需要认证
```

---

## 8. 安全加固措施

### 8.1 文件系统安全

```bash
# 1. 用户目录权限（由运维工具设置）
chmod 700 /home/zhangsan
chown cui-service:cui-service /home/zhangsan -R

# 2. 服务进程用户
# 创建专用系统用户运行 CUI 服务
sudo useradd -r -s /bin/false cui-service
sudo usermod -L cui-service  # 锁定密码，防止登录

# 3. 目录隔离验证脚本
cat > /usr/local/bin/verify-cui-permissions.sh <<'EOF'
#!/bin/bash
# 验证所有用户目录权限

for home_dir in /home/*; do
  if [ -d "$home_dir" ]; then
    username=$(basename "$home_dir")

    # 检查目录权限
    perms=$(stat -c %a "$home_dir")
    if [ "$perms" != "700" ]; then
      echo "WARNING: $home_dir has incorrect permissions: $perms (expected 700)"
    fi

    # 检查所有者
    owner=$(stat -c %U "$home_dir")
    if [ "$owner" != "cui-service" ]; then
      echo "WARNING: $home_dir has incorrect owner: $owner (expected cui-service)"
    fi
  fi
done
EOF

chmod +x /usr/local/bin/verify-cui-permissions.sh
```

### 8.2 进程资源限制

```bash
# /etc/security/limits.conf
cui-service soft nproc 2000      # 最大进程数
cui-service hard nproc 2500
cui-service soft nofile 10000    # 最大文件句柄数
cui-service hard nofile 15000
cui-service soft as 209715200    # 最大虚拟内存（200GB）
cui-service hard as 262144000    # 硬限制（250GB）
```

### 8.3 审计日志

```typescript
// src/services/audit-logger.ts

import Database from 'mysql2/promise';
import { createLogger } from './logger.js';

export class AuditLogger {
  private static instance: AuditLogger;
  private db!: Database.Connection;
  private logger = createLogger('AuditLogger');

  static getInstance(): AuditLogger {
    if (!AuditLogger.instance) {
      AuditLogger.instance = new AuditLogger();
    }
    return AuditLogger.instance;
  }

  async initialize(db: Database.Connection): Promise<void> {
    this.db = db;
  }

  /**
   * 记录审计日志
   */
  async log(params: {
    username: string;
    action: string;
    resourceType?: string;
    resourceId?: string;
    details?: Record<string, any>;
    ipAddress?: string;
    userAgent?: string;
    status: 'success' | 'failure';
    errorMessage?: string;
  }): Promise<void> {
    try {
      await this.db.execute(
        `INSERT INTO audit_logs
         (username, action, resource_type, resource_id, details,
          ip_address, user_agent, status, error_message)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        [
          params.username,
          params.action,
          params.resourceType || null,
          params.resourceId || null,
          JSON.stringify(params.details || {}),
          params.ipAddress || null,
          params.userAgent || null,
          params.status,
          params.errorMessage || null,
        ]
      );
    } catch (error) {
      this.logger.error('Failed to write audit log', { error, params });
    }
  }
}
```

### 8.4 速率限制

```typescript
// src/middleware/rate-limit.ts

import { Request, Response, NextFunction } from 'express';
import { createLogger } from '@/services/logger.js';

const logger = createLogger('RateLimit');

interface RateLimitStore {
  count: number;
  resetTime: number;
}

const store = new Map<string, RateLimitStore>();

/**
 * 速率限制中间件
 * @param maxRequests 时间窗口内最大请求数
 * @param windowMs 时间窗口（毫秒）
 */
export function rateLimitMiddleware(maxRequests: number = 100, windowMs: number = 60000) {
  return (req: Request, res: Response, next: NextFunction): void => {
    const username = req.user?.username || req.ip || 'anonymous';
    const now = Date.now();

    let record = store.get(username);

    // 清理过期记录
    if (record && now >= record.resetTime) {
      store.delete(username);
      record = undefined;
    }

    if (!record) {
      record = {
        count: 1,
        resetTime: now + windowMs,
      };
      store.set(username, record);
      next();
      return;
    }

    if (record.count >= maxRequests) {
      logger.warn('Rate limit exceeded', { username, count: record.count });
      res.status(429).json({
        error: 'Too many requests',
        retryAfter: Math.ceil((record.resetTime - now) / 1000),
      });
      return;
    }

    record.count++;
    next();
  };
}
```

---

## 9. 部署方案

### 9.1 服务器配置要求

```yaml
# 生产环境推荐配置
硬件:
  CPU: 16-32 核心
  内存: 128GB RAM
  磁盘: 500GB+ SSD
  网络: 千兆网卡

操作系统:
  推荐: Ubuntu 22.04 LTS
  备选: CentOS 8 / RHEL 8

数据库:
  MySQL: 8.0+ 或 PostgreSQL: 15+
  推荐配置: 16GB RAM, 200GB SSD

备份:
  数据库: 每日备份
  用户目录: 每周备份
```

### 9.2 系统初始化脚本

```bash
#!/bin/bash
# scripts/setup-server.sh

set -e

echo "CUI 多用户系统初始化脚本"
echo "================================"

# 1. 创建系统用户
echo "[1/6] 创建 CUI 服务用户..."
if ! id cui-service &>/dev/null; then
  sudo useradd -r -s /bin/false cui-service
  sudo usermod -L cui-service
  echo "✓ 用户 cui-service 创建成功"
else
  echo "✓ 用户 cui-service 已存在"
fi

# 2. 安装依赖
echo "[2/6] 安装系统依赖..."
sudo apt update
sudo apt install -y \
  nodejs \
  npm \
  mysql-server \
  firejail \
  gettext-base

echo "✓ 系统依赖安装完成"

# 3. 配置 MySQL
echo "[3/6] 配置 MySQL 数据库..."
sudo mysql -e "CREATE DATABASE IF NOT EXISTS cui_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
sudo mysql -e "CREATE USER IF NOT EXISTS 'cui'@'localhost' IDENTIFIED BY 'your-secure-password';"
sudo mysql -e "GRANT ALL PRIVILEGES ON cui_db.* TO 'cui'@'localhost';"
sudo mysql -e "FLUSH PRIVILEGES;"

echo "✓ 数据库配置完成"

# 4. 初始化数据库表
echo "[4/6] 初始化数据库表..."
sudo mysql cui_db < scripts/init-mysql-database.sql

echo "✓ 数据库表创建完成"

# 5. 设置资源限制
echo "[5/6] 配置资源限制..."
cat <<EOF | sudo tee -a /etc/security/limits.conf
cui-service soft nproc 2000
cui-service hard nproc 2500
cui-service soft nofile 10000
cui-service hard nofile 15000
EOF

echo "✓ 资源限制配置完成"

# 6. 创建配置目录
echo "[6/6] 创建配置目录..."
sudo mkdir -p /etc/cui
sudo chown cui-service:cui-service /etc/cui

# 创建服务器配置文件
cat <<EOF | sudo tee /etc/cui/server-config.json
{
  "server": {
    "host": "0.0.0.0",
    "port": 3000
  },
  "interface": {
    "colorScheme": "system",
    "language": "zh-CN"
  }
}
EOF

sudo chmod 600 /etc/cui/server-config.json
sudo chown cui-service:cui-service /etc/cui/server-config.json

echo "✓ 配置目录创建完成"

echo ""
echo "================================"
echo "✓ CUI 系统初始化完成"
echo ""
echo "下一步:"
echo "1. 编辑 /etc/cui/server-config.json 配置服务器参数"
echo "2. 配置环境变量（LDAP、JWT_SECRET 等）"
echo "3. 使用运维工具创建用户目录"
echo "4. 启动 CUI 服务"
```

### 9.3 Systemd 服务配置

```ini
# /etc/systemd/system/cui-server.service

[Unit]
Description=CUI Multi-User Server
After=network.target mysql.service

[Service]
Type=simple
User=cui-service
Group=cui-service
WorkingDirectory=/opt/cui-server

# 环境变量
Environment=NODE_ENV=production
Environment=LOG_LEVEL=info

# LDAP 配置
Environment=LDAP_URL=ldap://ldap.company.com:389
Environment=LDAP_BASE_DN=dc=company,dc=com

# JWT 配置
Environment=JWT_SECRET=your-secure-random-secret-here

# 数据库配置
Environment=DB_HOST=localhost
Environment=DB_PORT=3306
Environment=DB_USER=cui
Environment=DB_PASSWORD=your-secure-password
Environment=DB_NAME=cui_db

# 可选：启用 firejail 沙箱
Environment=USE_FIREJAIL=true

# 启动命令
ExecStart=/usr/bin/node /opt/cui-server/dist/server.js

# 重启策略
Restart=always
RestartSec=10

# 资源限制
LimitNOFILE=10000
LimitNPROC=2000

# 日志
StandardOutput=journal
StandardError=journal
SyslogIdentifier=cui-server

[Install]
WantedBy=multi-user.target
```

启动服务：

```bash
# 重新加载 systemd
sudo systemctl daemon-reload

# 启动服务
sudo systemctl start cui-server

# 设置开机自启
sudo systemctl enable cui-server

# 查看状态
sudo systemctl status cui-server

# 查看日志
sudo journalctl -u cui-server -f
```

### 9.4 Nginx 反向代理（可选）

```nginx
# /etc/nginx/sites-available/cui-server

upstream cui_backend {
  server 127.0.0.1:3000;
  keepalive 64;
}

server {
  listen 80;
  server_name cui.company.com;

  # 重定向到 HTTPS
  return 301 https://$server_name$request_uri;
}

server {
  listen 443 ssl http2;
  server_name cui.company.com;

  # SSL 证书
  ssl_certificate /etc/ssl/certs/cui.company.com.crt;
  ssl_certificate_key /etc/ssl/private/cui.company.com.key;

  # SSL 配置
  ssl_protocols TLSv1.2 TLSv1.3;
  ssl_ciphers HIGH:!aNULL:!MD5;
  ssl_prefer_server_ciphers on;

  # 日志
  access_log /var/log/nginx/cui-access.log;
  error_log /var/log/nginx/cui-error.log;

  # 客户端请求限制
  client_max_body_size 100M;
  client_body_timeout 300s;

  # 代理配置
  location / {
    proxy_pass http://cui_backend;
    proxy_http_version 1.1;

    # WebSocket 支持（用于 SSE）
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";

    # 代理头
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 超时设置（Claude 对话可能较长）
    proxy_connect_timeout 300s;
    proxy_send_timeout 300s;
    proxy_read_timeout 300s;

    # 缓冲设置
    proxy_buffering off;
  }

  # 健康检查端点
  location /health {
    proxy_pass http://cui_backend/api/system/health;
    access_log off;
  }
}
```

---

## 10. 实施计划

### 10.1 Phase 1: 基础架构改造（1-2 周）

**目标**：建立多用户基础框架

**任务清单**：

- [ ] 数据库设计和迁移
  - [ ] 设计用户表和会话表 schema
  - [ ] 编写数据库迁移脚本
  - [ ] 从 SQLite 迁移到 MySQL
  - [ ] 测试数据库连接和查询

- [ ] 认证系统实现（简化）
  - [ ] 实现网关认证中间件 (gateway-auth.ts)
  - [ ] 实现用户名格式验证（防注入）
  - [ ] 配置环境变量 GATEWAY_TOKEN
  - [ ] 安装 cookie-parser 依赖
  - [ ] ❌ 无需实现 LDAP 集成
  - [ ] ❌ 无需实现 JWT Token
  - [ ] ❌ 无需创建登录 API

- [ ] 用户目录管理
  - [ ] 实现 UserMappingService
  - [ ] 测试系统用户读取
  - [ ] 验证目录权限检查
  - [ ] 编写运维工具脚本（创建用户目录）

- [ ] 用户服务实现
  - [ ] 实现 UserService（数据库操作）
  - [ ] 实现用户信息查询
  - [ ] 实现配额管理
  - [ ] 实现用户偏好设置

**验收标准**：
- ✅ 网关认证中间件正确验证静态 Token
- ✅ 可以从 Cookie 读取用户名
- ✅ 用户名格式验证工作正常（防注入）
- ✅ 可以读取用户目录映射
- ✅ 用户上下文正确注入到 req.user

### 10.2 Phase 2: Claude CLI 多用户改造（2-3 周）

**目标**：实现 Claude CLI 多用户隔离

**任务清单**：

- [ ] ConfigService 改造
  - [ ] 改造为支持多用户配置加载
  - [ ] 实现用户配置缓存
  - [ ] 测试配置读取和合并

- [ ] ClaudeProcessManager 改造
  - [ ] 修改 ConversationConfig 类型
  - [ ] 实现用户上下文传递
  - [ ] 设置用户专属环境变量
  - [ ] 测试进程隔离

- [ ] ClaudeHistoryReader 改造
  - [ ] 支持读取用户专属历史记录
  - [ ] 测试历史记录隔离

- [ ] SessionInfoService 改造
  - [ ] 添加 user_id 字段
  - [ ] 实现按用户查询
  - [ ] 测试会话隔离

**验收标准**：
- ✅ 不同用户的 Claude CLI 使用各自的 HOME 目录
- ✅ 会话历史按用户隔离
- ✅ 配置文件正确加载
- ✅ 无交叉污染

### 10.3 Phase 3: 路由和 API 改造（1 周）

**目标**：所有 API 支持网关认证

**任务清单**：

- [ ] ❌ 无需实现认证路由（网关已完成认证）

- [ ] 用户路由
  - [ ] GET /api/users/me
  - [ ] PATCH /api/users/me/preferences
  - [ ] GET /api/users/me/quota

- [ ] 改造现有路由
  - [ ] 所有路由添加认证中间件
  - [ ] 传递用户上下文
  - [ ] 测试每个 API 端点

**验收标准**：
- ✅ 所有 API 需要认证才能访问
- ✅ 未认证请求返回 401
- ✅ 用户只能访问自己的资源

### 10.4 Phase 4: 安全加固（1-2 周）

**目标**：提升系统安全性

**任务清单**：

- [ ] 文件系统安全
  - [ ] 验证目录权限脚本
  - [ ] 设置文件权限规范
  - [ ] 测试目录隔离

- [ ] 进程安全
  - [ ] 配置系统资源限制
  - [ ] 集成 firejail（可选）
  - [ ] 测试进程隔离

- [ ] 审计日志
  - [ ] 实现 AuditLogger
  - [ ] 记录关键操作
  - [ ] 测试日志写入

- [ ] 速率限制
  - [ ] 实现速率限制中间件
  - [ ] 应用到关键 API
  - [ ] 测试限流效果

**验收标准**：
- ✅ 文件权限正确设置
- ✅ 关键操作有审计日志
- ✅ API 有速率限制
- ✅ 可选的沙箱功能正常

### 10.5 Phase 5: 前端改造和测试（1-2 周）

**目标**：前端支持多用户体验（无需登录页面）

**任务清单**：

- [ ] 前端改造（简化）
  - [ ] ❌ 无需登录页面（网关已完成）
  - [ ] ❌ 无需 Token 管理（网关处理）
  - [ ] 用户信息展示
  - [ ] 配额显示
  - [ ] 会话隔离提示

- [ ] 测试
  - [ ] 单元测试（网关认证中间件）
  - [ ] 集成测试（用户隔离验证）
  - [ ] 压力测试（2000 用户并发）
  - [ ] 安全测试（路径注入防护）

- [ ] 文档
  - [ ] 用户使用手册
  - [ ] 管理员手册（包括网关配置）
  - [ ] API 文档（更新认证方式）
  - [ ] 故障排查指南

**验收标准**：
- ✅ 用户通过网关访问系统（无感知登录）
- ✅ 测试覆盖率 > 80%
- ✅ 文档完善（包括网关集成说明）

### 10.6 Phase 6: 部署和上线（1 周）

**目标**：生产环境部署

**任务清单**：

- [ ] 生产环境准备
  - [ ] 服务器配置
  - [ ] 数据库部署
  - [ ] 环境变量配置
  - [ ] SSL 证书配置

- [ ] 部署
  - [ ] 代码部署
  - [ ] 数据库初始化
  - [ ] 服务启动
  - [ ] 健康检查

- [ ] 监控
  - [ ] 日志监控
  - [ ] 性能监控
  - [ ] 告警配置

- [ ] 用户迁移（如果有老数据）
  - [ ] 数据备份
  - [ ] 数据迁移
  - [ ] 验证数据完整性

**验收标准**：
- ✅ 系统在生产环境稳定运行
- ✅ 监控和告警正常
- ✅ 用户可以正常使用

### 10.7 时间线总结（基于网关认证简化方案）

| Phase | 任务 | 预计时间 | 累计时间 | 说明 |
|-------|------|---------|---------|------|
| Phase 1 | 基础架构改造 | 1-2 周 ✅ | 1-2 周 | 认证系统简化，节省 1 周 |
| Phase 2 | Claude CLI 改造 | 2-3 周 | 3-5 周 | 无变化 |
| Phase 3 | 路由和 API 改造 | 1 周 ✅ | 4-6 周 | 无需实现登录 API，节省时间 |
| Phase 4 | 安全加固 | 1-2 周 | 5-8 周 | 无变化 |
| Phase 5 | 前端和测试 | 1-2 周 ✅ | 6-10 周 | 无需登录页面，节省时间 |
| Phase 6 | 部署上线 | 1 周 | 7-11 周 | 无变化 |
| **总计** | | **1.5-2.5 个月** ✅ | | **相比原方案节省约 1 个月** |

---

## 11. 风险和注意事项

### 11.1 技术风险

| 风险 | 影响 | 缓解措施 |
|------|------|---------|
| Claude CLI 多用户并发问题 | 高 | 进程池管理，资源限制 |
| 文件系统隔离不完善 | 高 | 严格权限控制，可选沙箱 |
| 数据库性能瓶颈 | 中 | 索引优化，读写分离 |
| 用户配额耗尽 | 中 | 配额管理，告警通知 |

### 11.2 运维注意事项

1. **用户目录维护**
   - 定期检查目录权限
   - 监控磁盘使用量
   - 及时清理过期数据

2. **数据库维护**
   - 定期备份（每日）
   - 定期优化索引
   - 监控慢查询

3. **日志管理**
   - 日志轮转策略
   - 保留 30 天日志
   - 审计日志单独存储

4. **监控告警**
   - CPU 使用率 > 80%
   - 内存使用率 > 80%
   - 磁盘使用率 > 85%
   - 进程数 > 1800

### 11.3 安全建议

1. **定期安全审计**
   - 每季度审查访问日志
   - 检查异常行为
   - 更新安全补丁

2. **备份策略**
   - 数据库：每日全量备份
   - 用户目录：每周增量备份
   - 保留 30 天备份

3. **灾难恢复**
   - 制定恢复预案
   - 定期演练
   - RTO < 4 小时，RPO < 24 小时

---

## 12. 附录

### 12.1 环境变量清单

```bash
# .env.production

# Node 环境
NODE_ENV=production
LOG_LEVEL=info

# ✅ 网关认证配置（必需）
GATEWAY_TOKEN=your-secure-static-token-from-gateway

# 数据库配置（必需）
DB_HOST=localhost
DB_PORT=3306
DB_USER=cui
DB_PASSWORD=your-secure-database-password
DB_NAME=cui_db

# CUI 服务器配置
CUI_SERVER_CONFIG=/etc/cui/server-config.json
CUI_PORT=3000
CUI_HOST=0.0.0.0

# 可选：Firejail 沙箱
USE_FIREJAIL=true

# 可选：Gemini API
GOOGLE_API_KEY=your-gemini-api-key

# 可选：代理配置
HTTPS_PROXY=http://proxy.company.com:8080

# ❌ 不再需要的环境变量：
# LDAP_URL - 网关已完成 LDAP 认证
# LDAP_BASE_DN - 网关已完成 LDAP 认证
# JWT_SECRET - 不使用 JWT Token
```

### 12.2 常见问题排查

#### Q1: Claude CLI 无法启动

```bash
# 检查 Claude CLI 是否安装
which claude

# 检查用户目录权限
ls -la /home/username

# 检查环境变量
env | grep HOME
env | grep CLAUDE_HOME

# 查看日志
sudo journalctl -u cui-server -f
```

#### Q2: 用户无法登录

```bash
# 测试 LDAP 连接
ldapsearch -x -H ldap://ldap.company.com:389 \
  -D "uid=username,dc=company,dc=com" \
  -W -b "dc=company,dc=com"

# 检查数据库
mysql -u cui -p cui_db
SELECT * FROM users WHERE username='username';

# 检查日志
grep "authentication failed" /var/log/cui/server.log
```

#### Q3: 性能问题

```bash
# 检查系统资源
top
htop

# 检查 Claude CLI 进程数
ps aux | grep claude | wc -l

# 检查数据库连接
mysql -u cui -p -e "SHOW PROCESSLIST;"

# 检查慢查询
mysql -u cui -p -e "SELECT * FROM mysql.slow_log ORDER BY start_time DESC LIMIT 10;"
```

### 12.3 参考资料

- [Claude CLI 官方文档](https://docs.anthropic.com/claude/docs)
- [Node.js 最佳实践](https://github.com/goldbergyoni/nodebestpractices)
- [LDAP 认证指南](https://ldap.com/)
- [MySQL 安全配置](https://dev.mysql.com/doc/refman/8.0/en/security.html)
- [Firejail 文档](https://firejail.wordpress.com/)

---

## 版本历史

| 版本 | 日期 | 变更说明 | 作者 |
|------|------|---------|------|
| 1.0 | 2025-12-10 | 初始版本 | Claude |

---

**文档结束**
