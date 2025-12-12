# language: zh-CN
功能: CUI多用户架构改造
  作为企业IT管理员
  我需要将CUI从单用户应用改造为多用户系统
  以便支持2000名员工同时使用，并确保数据完全隔离

  背景:
    假如 系统已部署在生产环境
    并且 MySQL数据库已初始化
    并且 企业统一网关已配置Token注入

  规则: 重构后功能必须与重构前完全一致

    @refactor @critical @regression
    场景: 重构后用户对话功能保持不变
      假如 用户 "zhangsan" 已通过网关认证
      并且 用户配置目录 "/mnt/bdap/zhangsan/.cui" 存在
      当 用户启动一个新对话 "帮我写一个Python脚本"
      那么 Claude CLI进程应该成功启动
      并且 进程的有效用户应该是 "zhangsan"
      并且 对话响应应该正常返回
      并且 会话记录应该保存到数据库
      并且 功能行为应该与重构前完全一致

    @refactor @regression
    场景大纲: 所有核心功能保持一致
      假如 用户 "lisi" 已通过网关认证
      当 用户执行 "<操作>" 操作
      那么 操作结果应该与重构前一致
      并且 操作审计日志应该记录

      例子:
        | 操作           |
        | 启动对话       |
        | 查看会话历史   |
        | 上传文件       |
        | 修改用户偏好   |
        | 查询配额使用   |

  规则: 用户隔离必须完全有效

    @refactor @security @critical
    场景: 用户数据完全隔离
      假如 用户 "zhangsan" 已创建会话 "session-001"
      并且 用户 "lisi" 已通过网关认证
      当 用户 "lisi" 尝试查询所有会话
      那么 响应应该只包含 "lisi" 的会话
      并且 不应该看到 "zhangsan" 的会话 "session-001"

    @refactor @security
    场景: 文件系统权限隔离
      假如 用户 "zhangsan" 的工作区路径是 "/mnt/bdap/zhangsan/workspace"
      当 用户 "zhangsan" 的Claude CLI进程尝试访问 "/mnt/bdap/lisi/workspace"
      那么 操作应该被拒绝（Permission Denied）
      并且 审计日志应该记录此次尝试

    @refactor @security
    场景: 进程权限隔离验证
      假如 用户 "wangwu" 已通过网关认证
      当 CUI Server为用户启动Claude CLI进程
      那么 进程应该以 "wangwu" 用户身份运行（euid=wangwu）
      并且 进程只能访问 "/mnt/bdap/wangwu" 目录
      并且 进程不能访问其他用户的目录

  规则: 认证系统必须安全可靠

    @refactor @authentication @critical
    场景: 网关Token验证生效
      假如 客户端请求包含Header "X-Gateway-Token: valid-token"
      并且 客户端请求包含Cookie "dss_user_name=zhangsan"
      当 请求发送到 "/api/conversations/start"
      那么 请求应该通过认证
      并且 用户上下文应该正确注入（req.user.username=zhangsan）

    @refactor @authentication
    场景: 无效Token被拒绝
      假如 客户端请求包含无效的 "X-Gateway-Token"
      当 请求发送到 "/api/conversations/start"
      那么 请求应该返回401 Unauthorized
      并且 不应该执行任何业务逻辑

    @refactor @authentication
    场景: 用户名格式验证防止路径注入
      假如 客户端Cookie包含用户名 "../../../etc/passwd"
      当 请求发送到认证中间件
      那么 请求应该被拒绝（400 Bad Request）
      并且 应该记录安全日志

  规则: 配置系统支持多用户

    @refactor @configuration
    场景: 用户独立配置加载
      假如 用户 "zhangsan" 的配置文件 "/mnt/bdap/zhangsan/.cui/config.json" 内容为:
        """
        {
          "preferences": {"theme": "dark"},
          "feature_flags": {"enable_gemini": true}
        }
        """
      当 用户 "zhangsan" 首次访问系统
      那么 ConfigService应该加载用户专属配置
      并且 配置应该被缓存（避免重复读取）
      并且 不应该影响其他用户的配置

    @refactor @configuration
    场景: 配置文件不存在时使用默认配置
      假如 用户 "newuser" 的配置文件不存在
      当 系统尝试加载用户配置
      那么 应该使用默认配置
      并且 应该记录警告日志
      并且 不应该抛出错误

  规则: 进程生命周期管理有效

    @refactor @resource-management
    场景: 空闲进程自动回收
      假如 用户 "zhangsan" 的Claude CLI进程已启动
      并且 进程空闲时间超过5分钟
      当 进程生命周期管理器执行检查
      那么 该进程应该被自动终止
      并且 资源应该被释放
      并且 审计日志应该记录回收操作

    @refactor @resource-management
    场景: LRU进程淘汰策略
      假如 系统当前运行100个Claude CLI进程（达到上限）
      并且 新用户 "newuser" 请求启动对话
      当 系统检测到进程数达到上限
      那么 应该终止最久未活动的进程
      并且 为新用户启动新进程
      并且 旧进程的会话应该标记为"已分离"

    @refactor @resource-management
    场景: 前端断开连接后快速回收
      假如 用户 "zhangsan" 的SSE连接已建立
      并且 对应的Claude CLI进程正在运行
      当 用户关闭浏览器（SSE连接断开）
      那么 系统应该检测到连接断开
      并且 启动5分钟倒计时
      并且 如果用户未在5分钟内重连，则终止进程

  规则: 性能和可扩展性达标

    @refactor @performance
    场景: 支持200并发用户
      假如 有200个用户同时通过网关认证
      当 所有用户同时发起对话请求
      那么 系统应该在2秒内响应所有请求
      并且 所有进程应该正确启动
      并且 CPU使用率应该 < 80%
      并且 内存使用应该 < 100GB

    @refactor @performance
    场景: 数据库查询性能
      假如 数据库中有2000个用户记录
      并且 每个用户有平均50个会话记录
      当 用户 "zhangsan" 查询自己的会话列表
      那么 查询响应时间应该 < 100ms
      并且 应该正确使用索引（user_id索引）

  规则: 审计和监控完善

    @refactor @audit
    场景: 关键操作记录审计日志
      假如 用户 "zhangsan" 已通过网关认证
      当 用户执行以下操作:
        | 操作类型           |
        | start_conversation |
        | execute_bash       |
        | upload_file        |
      那么 每个操作应该在audit_logs表中有记录
      并且 记录应该包含: username、action、timestamp、ip_address、status

    @refactor @monitoring
    场景: 用户级日志分流
      假如 用户 "zhangsan" 的Claude CLI进程正在运行
      当 进程产生stdout和stderr输出
      那么 日志应该写入 "/mnt/bdap/zhangsan/.cui/logs/claude-cli-<date>.log"
      并且 不应该混杂在系统日志中

  规则: 安全加固措施生效

    @refactor @security
    场景: 速率限制防止恶意攻击
      假如 客户端IP "192.168.1.100" 在1秒内发送了15次API请求
      当 第11次请求到达
      那么 请求应该被拒绝（429 Too Many Requests）
      并且 应该记录速率限制日志

    @refactor @security
    场景: 文件权限验证
      假如 系统管理员运行权限验证脚本
      当 检查用户目录 "/mnt/bdap/zhangsan"
      那么 目录权限应该是 700
      并且 目录所有者应该是 "zhangsan:zhangsan"
      并且 配置文件权限应该是 600

  规则: 回滚机制可用

    @refactor @rollback
    场景: 阶段2进程隔离回滚
      假如 进程隔离改造导致Claude CLI无法启动
      当 管理员执行回滚操作
      那么 系统应该恢复到原始的ClaudeProcessManager（不使用sudo）
      并且 现有用户的会话应该能够继续
      并且 回滚应该在5分钟内完成

  规则: 用户体验保持一致

    @refactor @ux
    场景: 无感知登录体验
      假如 用户通过企业门户访问CUI
      当 企业网关完成认证并注入Token/Cookie
      那么 用户应该直接看到CUI界面（无需额外登录）
      并且 界面应该显示当前用户名和配额信息

    @refactor @ux
    场景: 配额接近上限时提示
      假如 用户 "zhangsan" 的配额上限是1000次
      并且 已使用950次
      当 用户启动新对话
      那么 界面应该显示配额警告提示
      并且 提示内容应该包含剩余次数（50次）

  规则: 兼容性保持良好

    @refactor @compatibility
    场景: 前端API向后兼容
      假如 现有前端使用旧版API接口 "/api/conversations/start"
      当 后端完成多用户改造
      那么 旧接口应该继续工作
      并且 响应格式应该保持一致
      并且 仅增加可选的用户上下文字段

    @refactor @compatibility
    场景: 历史数据迁移验证
      假如 旧系统有100条SQLite会话记录
      当 执行数据迁移脚本（SQLite → MySQL）
      那么 所有记录应该成功迁移
      并且 数据完整性应该保持（无数据丢失）
      并且 迁移后的会话应该关联到admin用户

  规则: 运维工具齐全

    @refactor @ops
    场景: 用户初始化脚本可用
      假如 管理员需要为新用户 "newuser" 创建环境
      当 管理员执行 "sudo bash scripts/init-user.sh newuser"
      那么 应该创建目录 "/mnt/bdap/newuser"
      并且 应该创建子目录 ".claude"、".cui"、"workspace"
      并且 应该设置正确的权限和所有者

    @refactor @ops
    场景: 健康检查端点可用
      当 监控系统访问 "/health" 端点
      那么 应该返回200 OK
      并且 响应应该包含系统状态信息:
        """
        {
          "status": "ok",
          "version": "0.6.3",
          "uptime": 86400,
          "activeProcesses": 50,
          "databaseConnected": true
        }
        """
