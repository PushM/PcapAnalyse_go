# PcapAnalyse_go

GO语言编写，调用gopacket。gopacket是google写的golang抓包库，针对libpcap和npcap进行封装，提供更方便的go接口。

代码实现解析的协议及相应字段：

| 协议    | 字段                                             |
| ------- | ------------------------------------------------ |
| Ethenet | 源mac、目的mac、上层协议类型                     |
| IP      | 源ip、目的ip                                     |
| TCP     | 源port、目的port、序列号                         |
| HTTP    | url、host、user-agent                            |
| TLS     | 类型、版本、密码套件、server name                |
| DNS     | 操作码、响应码、question中的domain、answer中的ip |

使用：

```shell
pcapAnalyse.exe -d **.pcap
```

