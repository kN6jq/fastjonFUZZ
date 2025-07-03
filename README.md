# FastJSON依赖FUZZ工具

一个用于检测FastJSON漏洞的图形化工具，可以自动测试各种Java类的反序列化漏洞。

## 功能特点

- **图形化界面**：简洁直观的操作界面
- **多种测试类别**：支持JNDI类、字节码执行、文件读写等多种漏洞类型测试
- **GET/POST请求支持**：支持GET和POST两种请求方式
  - POST请求：直接使用原始payload
  - GET请求：自动对payload进行URL编码
- **彩色结果输出**：不同类型的结果使用不同颜色显示，一目了然
- **代理支持**：可配置HTTP代理进行测试
- **自定义漏洞特征**：可自定义漏洞检测特征
- **自动URL解析**：智能处理URL路径，避免路径重复问题

## 使用方法

### 运行环境

- JDK 8+
- Maven 3.6+（仅构建需要）

### 构建与运行

#### 方法一：使用Maven构建

1. 克隆或下载项目代码
2. 进入项目根目录
3. 执行Maven构建命令：
   ```
   mvn clean package
   ```
4. 构建完成后，在target目录下会生成两个JAR文件：
   - `fastjonFUZZ-1.0-SNAPSHOT.jar`：不包含依赖的JAR
   - `fastjonFUZZ-1.0-SNAPSHOT-jar-with-dependencies.jar`：包含所有依赖的可执行JAR

5. 运行可执行JAR：
   ```
   java -jar target/fastjonFUZZ-1.0-SNAPSHOT-jar-with-dependencies.jar
   ```

#### 方法二：直接运行

如果您已经有了编译好的JAR文件，可以直接运行：

```
java -jar fastjonFUZZ-1.0-SNAPSHOT-jar-with-dependencies.jar
```

### 使用步骤

1. 配置测试参数：
   - 目标URL：输入要测试的目标URL（例如：`http://142.171.65.181/login`）
   - FUZZ位置：在HTTP请求数据包中标记要插入payload的位置（默认为"FUZZ"）
   - 请求方法：选择GET或POST
   - 漏洞特征：输入漏洞特征字符串（默认为"can not cast to char"）
   - 代理设置：如需使用代理，填写代理主机和端口
   - 超时设置：请求超时时间（毫秒）
   - 测试类别：选择要测试的漏洞类别

2. 编辑HTTP请求数据包：
   - 在左侧文本框中编辑HTTP请求数据包
   - 确保请求包中包含FUZZ标记位置
   - 示例请求包：
     ```
     POST /login HTTP/1.1
     Accept: text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
     User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool
     Accept-Encoding: gzip, deflate, br
     Content-Length: 106
     Content-Type: application/json
     Cache-Control: no-cache
     Pragma: no-cache
     Host: 142.171.65.181
     Connection: keep-alive
     
     FUZZ
     ```

3. 点击"开始测试"按钮开始测试
4. 测试过程中可以随时点击"停止测试"按钮停止测试
5. 测试完成后，可以点击"清空结果"按钮清空结果区域

### 结果说明

测试结果将在右侧文本框中显示，使用不同颜色标识不同类型的结果：
- **红色**：发现漏洞
- **绿色**：安全，未发现漏洞
- **黄色**：测试过程中出现错误
- **青色**：测试类别标题
- **白色**：正在测试的类名

## 工具原理

该工具通过向目标发送特制的JSON payload，检测服务器是否存在FastJSON反序列化漏洞。工具会测试多种Java类，这些类在反序列化过程中可能导致远程代码执行、信息泄露或其他安全问题。

FastJSON在解析JSON时，如果开启了autoType功能，会尝试将JSON反序列化为指定的Java类型。当服务器收到包含恶意类的JSON数据时，可能会触发漏洞。本工具通过检测服务器响应中的特定错误信息（如"can not cast to char"）来判断目标是否存在漏洞。

## 支持的漏洞类型

- **JNDI类**：测试JNDI注入相关的类
- **字节码&命令执行**：测试可能导致远程代码执行的类
- **文件读写**：测试可能导致文件操作的类
- **反序列化利用链**：测试常见的反序列化漏洞利用链
- **JDBC相关**：测试JDBC连接相关的类
- **WebSphere RCE**：测试WebSphere特定的远程代码执行漏洞
- **XXE与文件写入**：测试XXE和文件写入相关的类
- **辅助依赖环境判断**：测试环境依赖相关的类

## 常见问题

1. **请求路径重复问题**
   - 问题：发送的请求URL出现路径重复，如`/login/login`
   - 解决：工具已优化URL解析逻辑，避免路径重复问题

2. **中文乱码问题**
   - 问题：结果显示中出现中文乱码
   - 解决：已使用UTF-8编码和合适的字体设置解决乱码问题

3. **特殊字符显示问题**
   - 问题：特殊符号（如emoji）显示异常
   - 解决：已移除特殊符号，使用彩色文本代替

4. **测试速度过慢**
   - 问题：测试所有类别需要较长时间
   - 解决：可以选择特定类别进行测试，减少测试时间

## 注意事项

- 本工具仅用于安全测试和研究目的
- 请在获得授权的情况下使用本工具
- 不要对未授权的系统进行测试
- 对测试结果负责，避免造成系统损害

## 开发者

- jiu 