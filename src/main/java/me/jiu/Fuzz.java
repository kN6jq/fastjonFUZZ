package me.jiu;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Fuzz {
    public static final Map<String, List<String>> GADGET_CLASSES = new HashMap<>();
    static {
        GADGET_CLASSES.put("JNDI类", Arrays.asList(
                "com.sun.rowset.JdbcRowSetImpl",
                "org.apache.shiro.jndi.JndiObjectFactory",
                "org.apache.shiro.realm.jndi.JndiRealmFactory",
                "com.mchange.v2.c3p0.JndiRefForwardingDataSource",
                "com.mchange.v2.c3p0.JndiRefConnectionPoolDataSource",
                "org.apache.commons.configuration.JNDIConfiguration",
                "org.apache.commons.configuration2.JNDIConfiguration",
                "org.apache.ibatis.datasource.jndi.JndiDataSourceFactory",
                "org.apache.commons.proxy.provider.remoting.SessionBeanProvider",
                "com.caucho.config.types.ResourceRef",
                "org.apache.ignite.cache.jta.jndi.CacheJndiTmLookup",
                "com.ibatis.sqlmap.engine.transaction.jta.JtaTransactionConfig",
                "br.com.anteros.dbcp.AnterosDBCPConfig",
                "org.apache.hadoop.shaded.com.zaxxer.hikari.HikariConfig",
                "org.apache.xbean.propertyeditor.JndiConverter",
                "oracle.jdbc.connector.OracleManagedConnectionFactory",
                "org.apache.cocoon.components.slide.impl.JMSContentInterceptor",
                "org.apache.aries.transaction.jms.internal.XaPooledConnectionFactory",
                "org.apache.aries.transaction.jms.RecoverablePooledConnectionFactory"
        ));
        GADGET_CLASSES.put("字节码&命令执行", Arrays.asList(
                "org.apache.ibatis.type.Alias",
                "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
                "org.apache.tomcat.dbcp.dbcp.BasicDataSource",
                "org.apache.tomcat.dbcp.dbcp2.BasicDataSource",
                "com.sun.org.apache.bcel.internal.util.ClassLoader",
                "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",
                "javax.el.ELProcessor",
                "groovy.lang.GroovyShell",
                "groovy.lang.GroovyClassLoader",
                "org.apache.naming.factory.BeanFactory",
                "org.yaml.snakeyaml.Yaml",
                "com.thoughtworks.xstream.XStream",
                "org.xmlpull.v1.XmlPullParserException",
                "org.xmlpull.mxp1.MXParser",
                "org.mvel2.sh.ShellSession",
                "com.sun.glass.utils.NativeLibLoader",
                "javax.management.loading.MLet"));
        GADGET_CLASSES.put("文件读写", Arrays.asList(
                "org.apache.commons.io.file.Counters",
                "org.apache.commons.io.Charsets",
                "org.aspectj.ajde.Ajde"));
        GADGET_CLASSES.put("反序列化利用链", Arrays.asList(
                "com.mysql.jdbc.Buffer",
                "com.mysql.cj.protocol.AuthenticationProvider",
                "com.mysql.cj.api.authentication.AuthenticationProvider",
                "org.codehaus.groovy.control.CompilerConfiguration",
                "org.apache.commons.collections.functors.InvokerTransformer",       // CC1/CC3/CC7/CC31/CC40/CC41/CC322
                "org.apache.commons.collections4.functors.InvokerTransformer",     // CC4+ (CommonsCollections4)
                "org.apache.commons.collections.functors.ChainedTransformer",      // 组合Transformer
                "org.apache.commons.collections.functors.ConstantTransformer",
                "org.apache.commons.collections4.functors.ChainedTransformer",
                "org.apache.commons.collections4.functors.ConstantTransformer",
                "org.apache.commons.collections.functors.MapEntryTransformer",
                "org.apache.commons.collections4.functors.MapEntryTransformer",
                "org.apache.commons.collections.map.LazyMap",
                "org.apache.commons.collections.keyvalue.TiedMapEntry",
                "org.apache.commons.collections.map.TransformedMap",
                "org.apache.commons.collections.map.PredicatedMap",
                "org.apache.commons.collections.functors.InstantiateTransformer",
                "org.apache.commons.collections.functors.ConstantTransformer",
                "org.apache.commons.collections.functors.FactoryTransformer",
                "org.apache.commons.collections4.map.LazyMap",
                "org.apache.commons.collections4.keyvalue.TiedMapEntry",
                "org.apache.commons.collections4.map.TransformedMap",
                "org.apache.commons.collections4.map.PredicatedMap",
                "org.apache.commons.collections4.functors.InstantiateTransformer",
                "org.apache.commons.collections4.functors.InvokerTransformer",
                "org.apache.commons.collections4.functors.ChainedTransformer",
                "org.apache.commons.collections4.functors.ConstantTransformer",
                "org.apache.commons.collections4.functors.FactoryTransformer",
                "org.apache.commons.beanutils.BeanComparator",
                "org.apache.commons.logging.LogFactory",// CB17/CB18x/CB19x
                "org.apache.commons.beanutils.PropertyUtilsBean",
                "com.sun.syndication.feed.impl.ObjectBean",                        // ROME1000/ROME1111
                "groovy.lang.GroovyShell",                                         // Groovy1702311、Groovy24x、Groovy244
                "groovy.lang.GroovyClassLoader",
                "com.mchange.v2.c3p0.WrapperConnectionPoolDataSource",             // C3P0 0.9.5.x
                "com.mchange.v2.c3p0.JndiRefForwardingDataSource",                 // C3P0 0.9.2.x
                "bsh.XThis",                                                       // Bsh20b4/5/6
                "com.fasterxml.jackson.databind.node.POJONode",                    // Jackson 默认反序列化Gadget点
                "com.fasterxml.jackson.databind.ObjectMapper",
                "com.alibaba.fastjson.JSONObject",
                "com.alibaba.fastjson.parser.ParserConfig",
                "sun.reflect.annotation.AnnotationInvocationHandler",              // Jdk7u21
                "sun.rmi.server.UnicastRef",                                       // RMI 链基础组件
                "javax.management.BadAttributeValueExpException",                 // JRE8u20
                // AspectJ Ajw
                "org.aspectj.weaver.tools.cache.DefiningClassLoader",
                "org.aspectj.weaver.tools.GeneratedClassHandler",
                "org.apache.bcel.util.ClassLoader"));
        GADGET_CLASSES.put("JDBC相关", Arrays.asList(
                "org.h2.Driver",
                "org.postgresql.Driver",
                "com.mysql.jdbc.Driver",
                "com.mysql.cj.jdbc.Driver",
                "org.h2.jdbcx.JdbcDataSource",
                "com.mysql.fabric.jdbc.FabricMySQLDriver",
                "oracle.jdbc.driver.OracleDriver",
                "org.apache.tomcat.dbcp.dbcp.BasicDataSourceFactory",
                "org.apache.tomcat.dbcp.dbcp2.BasicDataSourceFactory",
                "org.apache.commons.dbcp.BasicDataSourceFactory",
                "org.apache.commons.dbcp2.BasicDataSourceFactory",
                "org.apache.commons.pool.KeyedObjectPoolFactory",
                "org.apache.commons.pool2.PooledObjectFactory",
                "org.apache.tomcat.jdbc.pool.DataSourceFactory",
                "org.apache.juli.logging.LogFactory",
                "com.alibaba.druid.pool.DruidDataSourceFactory"
        ));
        GADGET_CLASSES.put("WebSphere RCE", Arrays.asList(
                "com.ibm.ws.client.applicationclient.ClientJ2CCFFactory",
                "com.ibm.ws.webservices.engine.client.ServiceFactory"
        ));
        GADGET_CLASSES.put("XXE与文件写入", Arrays.asList(
                "org.apache.catalina.UserDatabase",
                "org.apache.catalina.users.MemoryUserDatabaseFactory"
        ));
        GADGET_CLASSES.put("辅助依赖环境判断", Arrays.asList(
                "org.springframework.web.bind.annotation.RequestMapping",
                "org.apache.catalina.startup.Tomcat",
                "com.mchange.v2.c3p0.DataSources"
        ));
        GADGET_CLASSES.put("JDK 6 特征类", Arrays.asList(
                "sun.nio.cs.UTF_8",                     // 存在于 JDK6，也存在于后续，但JDK6中用于默认编码判断
                "sun.misc.BASE64Encoder",              // JDK6 存在，JDK8 后废弃，被 java.util.Base64 替代
                "sun.misc.Unsafe",                     // 早期版本更常见，JDK9+被封装，JDK6可直接用反射调用
                "java.util.Date",                      // JDK6主力时间类，JDK8后被java.time.*替代
                "java.util.Calendar",
                "com.sun.xml.internal.ws.client.AsyncResponseImpl", // JDK6 内置 WebService 实现类
                "javax.xml.bind.JAXBContext",          // JDK6 内置 XML 绑定 API，JDK11 移除需手动引入
                "com.sun.tools.javac.Main",            // Java Compiler Tools - javac 主类
                "com.sun.tools.javadoc.Main",          // Javadoc 工具类
                "com.sun.security.auth.module.UnixLoginModule",  // JDK6 标准模块之一，部分在JDK8后移除
                "javax.swing.plaf.metal.MetalLookAndFeel"        // Swing 中经典主题类
        ));
        GADGET_CLASSES.put("JDK 7 特征类", Arrays.asList(
                "java.nio.file.Path", // NIO.2 文件系统 API（JDK 7 引入）
                "java.nio.file.Files",
                "java.nio.file.attribute.BasicFileAttributes",
                "java.nio.file.StandardWatchEventKinds",
                "java.nio.file.WatchService",
                "java.lang.AutoCloseable",                // try-with-resources 和 AutoCloseable
                "java.util.Objects",                  // java.util.Objects 工具类（JDK 7 新增）
                "java.util.concurrent.ForkJoinPool",                 // Fork/Join 并发框架（JDK 7 引入）
                "java.util.concurrent.ForkJoinTask",                 // com.sun.nio（扩展支持 NIO）
                "com.sun.nio.zipfs.ZipFileSystemProvider"  // JDK 7 内置 zip 文件系统支持
        ));
        GADGET_CLASSES.put("JDK 8 特征类", Arrays.asList(
                "sun.nio.cs.GBK",
                "java.util.Spliterator",
                "java.util.concurrent.CompletableFuture",
                "java.util.Optional",
                "java.util.stream.Stream",
                "java.time.LocalDate",
                "java.time.LocalTime",
                "java.time.LocalDateTime",
                "java.time.Duration",
                "java.time.Period",
                "java.time.Instant",
                "java.util.function.Function",
                "java.util.function.Predicate",
                "java.util.function.Supplier",
                "java.util.function.Consumer",
                "java.time.format.DateTimeFormatter"
        ));
        GADGET_CLASSES.put("JDK 9+ 特征类", Arrays.asList(
                "java.lang.Module",
                "java.util.concurrent.Flow",
                "java.lang.invoke.VarHandle",
                "java.util.OptionalInt",
                "java.util.OptionalLong",
                "java.util.OptionalDouble",
                "java.net.http.HttpClient",
                "java.lang.StackWalker",
                "java.nio.file.Files"
        ));
        GADGET_CLASSES.put("JDK 11 特征类", Arrays.asList(
                "java.net.http.HttpClient",
                "java.lang.invoke.ConstantBootstraps",
                "java.util.concurrent.Flow",
                "java.nio.file.Files"
        ));
        GADGET_CLASSES.put("JDK 14 特征类", Arrays.asList(
                "java.lang.Record",
                "java.lang.constant.Constable"
        ));
        GADGET_CLASSES.put("JDK 15 特征类", Arrays.asList(
                "java.net.http.HttpRequest",
                "java.net.http.HttpResponse"
        ));
        GADGET_CLASSES.put("JDK 16 特征类", Arrays.asList(
                "java.util.random.RandomGenerator"
        ));
        GADGET_CLASSES.put("JDK 17 特征类", Arrays.asList(
                "java.net.spi",
                "java.util.random.RandomGeneratorFactory"
        ));
    }
}
