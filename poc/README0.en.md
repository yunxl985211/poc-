# Vulhub POC - Proof of Concept Collection

## Description
This directory contains Proof of Concept (POC) programs developed based on detailed vulnerability documentation in the Vulhub project. Each POC provides standardized vulnerability verification functionality.

## Requirements
- Python 3.6+
- requests library (`pip install requests`)

## Usage
```bash
# Check vulnerability only (no exploitation)
python CVE-2021-44228.py http://target:8983 --check-only

# Exploit vulnerability (execute command)
python CVE-2021-44228.py http://target:8983 --command "id"

# Debug with proxy
python CVE-2021-44228.py http://target:8983 --proxy http://127.0.0.1:8080

# JSON output
python CVE-2021-44228.py http://target:8983 --output json
```

Common CLI parameters supported by all POCs:
- `--check-only` Detection only
- `--command` / `-c` Command to execute
- `--proxy` / `-p` HTTP proxy
- `--timeout` / `-t` Request timeout
- `--insecure` / `-k` Skip SSL verification
- `--output text|json` Output format
- `-v` Verbose/Debug output

## POC List (51 total)

### RCE - Remote Code Execution
| File | Vulnerability | Type |
|------|-------------|------|
| CVE-2014-3120.py | ElasticSearch MVEL RCE | RCE |
| CVE-2015-5254.py | ActiveMQ Deserialization RCE | RCE |
| CVE-2017-5638.py | Struts2 S2-045 OGNL RCE | RCE |
| CVE-2017-10271.py | WebLogic XMLDecoder RCE | RCE |
| CVE-2018-7600.py | Drupal Drupalgeddon2 RCE | RCE |
| CVE-2019-15107.py | Webmin password_change RCE | RCE |
| CVE-2019-3396.py | Confluence Path Traversal SSTI RCE | RCE |
| CVE-2019-7609.py | Kibana Timelion RCE | RCE |
| CVE-2019-9082.py | ThinkPHP5 Invokefunction RCE | RCE |
| CVE-2020-7961.py | Liferay Portal Deserialization RCE | RCE |
| CVE-2020-9484.py | Tomcat Session Persistence RCE | RCE |
| CVE-2020-10199.py | Nexus EL Injection RCE | RCE |
| CVE-2020-11651.py | SaltStack ClearFuncs RCE | RCE |
| CVE-2020-11978.py | Airflow Example DAG RCE | RCE |
| CVE-2020-13945.py | Apache APISIX Lua RCE | RCE |
| CVE-2020-14882.py | WebLogic Console RCE | RCE |
| CVE-2021-21311.py | Adminer SSRF RCE | RCE |
| CVE-2021-21351.py | XStream Deserialization RCE | RCE |
| CVE-2021-22205.py | GitLab ExifTool RCE | RCE |
| CVE-2021-22911.py | RocketChat NoSQL RCE | RCE |
| CVE-2021-25646.py | Apache Druid JS RCE | RCE |
| CVE-2021-26084.py | Confluence OGNL RCE | RCE |
| CVE-2021-29442.py | Nacos Derby JNDI RCE | RCE |
| CVE-2021-29505.py | XStream Deserialization RCE v2 | RCE |
| CVE-2021-3129.py | Laravel Ignition RCE | RCE |
| CVE-2021-44228.py | Log4j2 JNDI Injection RCE | RCE |
| CVE-2021-44790.py | Apache mod_lua Buffer Overflow RCE | RCE |
| CVE-2021-45232.py | APISIX Dashboard RCE | RCE |
| CVE-2022-22947.py | Spring Cloud Gateway SpEL RCE | RCE |
| CVE-2022-22963.py | Spring Cloud Function SpEL RCE | RCE |
| CVE-2022-22965.py | Spring4Shell RCE | RCE |
| CVE-2023-46604.py | ActiveMQ OpenWire RCE | RCE |

### Code Injection - SQL/Command/Expression
| File | Vulnerability | Type |
|------|-------------|------|
| CVE-2016-4437.py | Shiro RememberMe RCE | Deserialization |
| CVE-2019-14234.py | Django JSONField SQLi | SQL Injection |
| CVE-2021-35042.py | Django ORDER BY SQLi | SQL Injection |
| CVE-2023-25157.py | GeoServer OGC Filter SQLi | SQL Injection |
| CVE-2020-17526.py | Airflow XSS Session Forge | Session Forge |
| CVE-2022-0543.py | Redis Lua Sandbox Escape | Sandbox Escape |

### Auth Bypass / Privilege Escalation
| File | Vulnerability | Type |
|------|-------------|------|
| CVE-2021-29441.py | Nacos Auth Bypass | Auth Bypass |
| CVE-2021-4034.py | Polkit pkexec LPE | LPE |
| CVE-2023-22515.py | Confluence Auth Bypass | Auth Bypass |
| CVE-2023-42793.py | TeamCity Auth Bypass RCE | Auth Bypass |
| CVE-2022-22978.py | Spring Security Regex Bypass | Auth Bypass |

### File Read / Path Traversal
| File | Vulnerability | Type |
|------|-------------|------|
| CVE-2020-1938.py | Tomcat Ghostcat AJP File Read | File Read |
| CVE-2021-41773.py | Apache HTTP Path Traversal | Path Traversal |
| CVE-2021-43798.py | Grafana Path Traversal | Path Traversal |
| CVE-2021-34429.py | Jetty Path Normalization | Info Disclosure |
| CVE-2023-51449.py | Gradio LFI | File Read |
| CVE-2024-23897.py | Jenkins CLI File Read | File Read |

### Other
| File | Vulnerability | Type |
|------|-------------|------|
| CVE-2019-17558.py | Apache Solr Velocity RCE | Template Injection |
| CVE-2022-26134.py | Confluence OGNL Pre-auth RCE | OGNL Injection |
