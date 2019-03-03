# hack
渗透测试资源库

收集各类渗透测试 信息安全相关的书籍 视频 思维导图

QQ 569743
https://www.ddosi.com/

爆破 未授权访问 远程代码执行 Java反序列 webshell 弱口令 认证绕过 缓冲区溢出注入攻击 Shift后门 TNS注入攻击

攻击木马 定制端口 自我销毁 捆绑文件 修改图标 恶意程序破坏网站 捆绑在启动文件中 隐形于启动组中 在驱动程序中藏身 内置到注册表中 伪装在普通文件中 盗取我们的网游账号，威胁我们的虚拟财产的安全


黑盒测试 白盒测试 开源安全测试方法论

信息系统安全评估框架

开放式Web 应用安全项目

Web 应用安全联合威胁分类

渗透测试执行标准:事前互动；

情报收集；

威胁建模；

漏洞分析；

漏洞利用；

深度利用；

书面报告

恶意软件集合

匿名代理

蜜罐

恶意软件样本库

开源威胁情报

检测与分类

在线扫描与沙盒

域名分析

浏览器恶意软件

判断是否有注入﻿ 初步判断是否是mssql 判断数据库系统 注入参数是字符 搜索时没过滤参数的 猜数据库 猜字段 猜字段中记录长度﻿ 猜字段的ascii值（access） 猜字段的ascii值（mssql） 测试权限结构（mssql）添加mssql和系统的帐户 遍历目录
渗透测试信息收集续 服务器信息 DNS枚举 敏感目录发掘 主机发现
端口扫描
版本侦测
oS侦测 A 地址记录
AAAA 地址记录
AFSDB Andrew文件系统数据库服务器记录
ATMA ATM地址记录
CNAME 别名记录
HINFO 硬件配置记录，包括CPU、操作系统信息
ISDN 域名对应的ISDN号码
MB 存放指定邮箱的服务器
MG 邮件组记录
MINFO 邮件组和邮箱的信息记录
MR 改名的邮箱记录
MX 邮件服务器记录
NS 名字服务器记录
PTR 反向记录
RP 负责人记录
RT 路由穿透记录
SRV TCP服务器信息记录
TXT 域名对应的文本信息
X25 域名对应的X.25地址记录

Mysql数据库渗透及漏洞利用总结
 Mysql信息收集
端口信息收集
版本信息收集
数据库管理信息收集
msf信息收集模块
Mysql密码获取
暴力破解
源代码泄露
文件包含
其它情况
Mysql获取webshell
phpmyadminroot账号获取webshell
sqlmap注入点获取webshell
Mysql提权
mof提权
Webshell上传mof文件提权
生成nullevtmof文件
通过Mysql查询将文件导入
Msf直接mof提权
UDF提权
sqlmap直连数据库提权
启动项提权
Msf其它相关漏洞提权
mysql密码破解
cain工具破解mysql密码
网站在线密码破解
oclhash破解
 John the Ripper password cracker
 
 渗透测试工程师子域名收集指南
	子域名枚举 
	在Google搜索中使用“site:”操作符查找子域名 
	用VirusTotal找到子域名 
	使用DNSdumpster查找子域名 
	使用Sublist3r进行子域名枚举 
	使用crt.sh查找一个组织主域名的子域名
