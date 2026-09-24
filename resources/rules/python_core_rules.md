# Python 核心审查规则库（白盒版）

> 从 bandit 拆解的最常用规则。每条规则白盒写清楚：查什么、怎么判断、例子。
> 作为 bandit 的本地 fallback——bandit 挂了我们自己也能跑。

---

## 三层审查框架（总纲）

> **核心原则**：不盲目找 bug。先建真值基准，再按规则审，最后防死循环。

### 第一序列：PEF 真值基准（先做，不做后面都是瞎找）

**目标**：搞清楚"这段代码本来应该干什么"，建立判断标准。

任何代码都是 **P（主体）→ E（变量）→ F（结果）** 三元结构：

| 拆解 | 要回答的问题 |
|---|---|
| **P 主体** | 这个函数/模块/类是干什么的？边界在哪？有没有越权做别的事？ |
| **E_in 可控输入** | 参数、配置——有没有做边界校验？是从配置读还是硬编码？ |
| **E_out 不可控输入** | 外部数据、文件、网络——有没有防御策略？ |
| **F 结果** | 输出能不能追溯到 (P, E, t)？出问题时日志里有没有业务上下文？ |

**怎么靠近真值**：
1. 先读函数名 + docstring，猜它应该干什么
2. 再读代码，看实际做了什么
3. 对比"应该"和"实际"——差距就是 bug

> 没有这个基准，后面所有规则都是机械匹配，不知道什么是真问题、什么是风格问题。

---

### 第二序列：规则审核标准（按表查）

第一序列建立了真值基准后，用下面的规则逐条对照。每条规则都对应一个 PEF 断裂点：

| PEF 断裂点 | 对应规则 | 严重级 |
|---|---|---|
| E_in 硬编码 | P-013 硬编码绝对路径 | P2 |
| F 不可追溯 | P-011 日志缺业务上下文 | P3 |
| P 没抽象 | P-012 重复 try/close 块 | P3（语义判断） |
| E 没分流 | P-014 业务路径用宽 except | P2（语义判断） |

---

### 第三序列：防死循环机制（最后做，防止越改越坏）

**原则**：不是所有"问题"都要修。修错了比不修更糟。

#### 什么情况不修（直接放过）：
1. **批处理容错设计**：`except Exception` 是刻意的——比如导出 Excel 时一行失败不影响其他行
2. **__main__ 自测代码**：硬编码路径是开发机示例，不进生产
3. **窄类型异常**：`except OSError`、`except ImportError` 是精确的，不是过宽
4. **已加日志的**：原来静默吞错已经加了 warning，不是新问题
5. **PEF_Core 冻结内核**：任何情况不改，除非单独授权

#### 什么情况必须修（阻断）：
1. P0：空指针、除零、命令注入、代码注入——会崩或被攻击
2. P1：业务路径静默吞错、硬编码密钥、反序列化漏洞——会丢数据或泄密
3. 交叉验证：两个以上工具同时报同一位置——可信度高

#### 什么情况先报告不擅自改：
1. 一个工具单独报的——可能是误报
2. 不在授权文件清单里的——先问
3. 修了可能影响业务逻辑的——先报告影响面

---

## 一、安全类（P0/P1）

### P-001 代码注入
**严重级：P0**

**查什么**：eval/exec 用了用户输入。

**怎么判断**：
```
模式：eval(user_input) / exec(user_input) —— 用户输入直接执行
```

**坏例子**：
```python
user_code = request.args.get('code')
eval(user_code)  # ❌ 用户可以执行任意代码
```

**好例子**：
```python
# 不要用 eval，用 ast.literal_eval
import ast
data = ast.literal_eval(user_input)  # ✅ 只解析字面量，不执行代码
```

---

### P-002 命令注入
**严重级：P0**

**查什么**：os.system / subprocess(shell=True) 用了用户输入。

**怎么判断**：
```
模式1：os.system(f"ls {user_input}")
模式2：subprocess.run(cmd, shell=True) —— cmd 里有用户输入
```

**坏例子**：
```python
import os
filename = request.args.get('file')
os.system(f"cat {filename}")  # ❌ filename="; rm -rf /" 就完了
```

**好例子**：
```python
import subprocess
# 不用 shell=True，参数传列表
subprocess.run(["cat", filename])  # ✅ 不会被 shell 解析
```

---

### P-003 硬编码密钥
**严重级：P1**

**查什么**：代码里写死了 API key / 密码 / token。

**怎么判断**：
```
模式1：sk-[a-zA-Z0-9]{32} —— OpenAI API key
模式2：AKIA[0-9A-Z]{16} —— AWS Access Key
模式3：ghp_[a-zA-Z0-9]{36} —— GitHub Token
模式4：password = "xxx" —— 写死的密码
```

**坏例子**：
```python
API_KEY = "sk-72e8c8e29bc74072868a3359a640ab1b"  # ❌ 直接写在代码里
```

**好例子**：
```python
import os
API_KEY = os.environ.get("API_KEY")  # ✅ 从环境变量读
```

---

### P-004 反序列化漏洞
**严重级：P0**

**查什么**：pickle.loads 用了不可信数据。

**怎么判断**：
```
模式：pickle.loads(user_input) —— pickle 可以执行任意代码
```

**坏例子**：
```python
import pickle
data = pickle.loads(request.body)  # ❌ 恶意数据可以执行任意代码
```

**好例子**：
```python
import json
data = json.loads(request.body)  # ✅ JSON 是安全的
```

---

## 二、错误处理类（P1/P2）

### P-005 静默吞错
**严重级：P1**

**查什么**：except Exception 抓了异常什么都不做。

**怎么判断**：
```
模式：
try:
    something()
except Exception:
    pass  # ❌ 抓了异常什么都不做，问题被吞了
```

**坏例子**：
```python
try:
    db.commit()
except Exception:
    pass  # ❌ 提交失败了但没人知道
```

**好例子**：
```python
try:
    db.commit()
except Exception as e:
    logger.error(f"提交失败: {e}")  # ✅ 至少记个日志
    raise  # 或者重新抛出
```

---

### P-006 裸 except
**严重级：P2**

**查什么**：except: 不指定异常类型，抓所有异常。

**怎么判断**：
```
模式：try: ... except: ... —— 连 KeyboardInterrupt 都抓了
```

**坏例子**：
```python
try:
    process()
except:
    pass  # ❌ 用户按 Ctrl+C 都退不出来
```

**好例子**：
```python
try:
    process()
except Exception as e:
    logger.error(f"出错了: {e}")
```

---

## 三、Python 特有陷阱（P2/P3）

### P-007 可变默认参数
**严重级：P2**

**查什么**：函数参数用了 mutable 默认值（list/dict）。

**怎么判断**：
```
模式：def f(x=[]): —— 默认值在函数定义时创建一次，所有调用共享
```

**坏例子**：
```python
def add_item(item, lst=[]):  # ❌ lst 只创建一次，所有调用共享
    lst.append(item)
    return lst

add_item(1)  # [1]
add_item(2)  # [1, 2] —— 不是预期的 [2]
```

**好例子**：
```python
def add_item(item, lst=None):
    if lst is None:
        lst = []  # ✅ 每次调用都新建一个 list
    lst.append(item)
    return lst
```

---

### P-008 可变迭代中删除元素
**严重级：P2**

**查什么**：for 循环里删 list 元素，导致跳项。

**怎么判断**：
```
模式：
for item in lst:
    if condition:
        lst.remove(item)  # ❌ 删了之后索引变了，下一个元素被跳过
```

**坏例子**：
```python
for i in lst:
    if i < 0:
        lst.remove(i)  # ❌ 会跳过元素
```

**好例子**：
```python
# 方法1：倒序遍历
for i in range(len(lst)-1, -1, -1):
    if lst[i] < 0:
        del lst[i]

# 方法2：列表推导式
lst = [x for x in lst if x >= 0]
```

---

### P-009 字符串拼接性能
**严重级：P3**

**查什么**：循环里用 += 拼字符串。

**怎么判断**：
```
模式：
s = ""
for item in items:
    s += str(item)  # ❌ 字符串不可变，每次都新建
```

**坏例子**：
```python
s = ""
for i in range(1000):
    s += str(i)  # ❌ O(n²) 性能
```

**好例子**：
```python
parts = []
for i in range(1000):
    parts.append(str(i))
s = "".join(parts)  # ✅ O(n) 性能
```

---

## 四、类型与空值（P2）

### P-010 空值未检查
**严重级：P1**

**查什么**：函数返回可能是 None，没检查就用。

**怎么判断**：
```
模式：
result = get_user(id)
print(result.name)  # ❌ result 可能是 None，直接崩
```

**坏例子**：
```python
user = db.get_user(id)
print(user.name)  # ❌ user 不存在时是 None
```

**好例子**：
```python
user = db.get_user(id)
if user is None:
    raise ValueError("用户不存在")
print(user.name)
```

---

## 五、PEF 结构类（P2/P3）

> 这 4 条是 2026-09-24 基于第一性原理新增的，对应 AI 代码的典型通病。

### P-013 硬编码绝对路径
**严重级：P2**
**PEF 对应：E_in 硬编码（应该是配置变量，不该绑死在主体里）**

**查什么**：代码里写死了 Windows 绝对路径 `D:\...` / `C:\...`。

**怎么判断**：
```
模式：[rf]?["'][A-Z]:[\\/][^"']*["']
```

**坏例子**：
```python
candidates = [
    r'D:\810\SI\CRO202608312439.xlsx',  # ❌ 换台电脑路径就不对
]
```

**好例子**：
```python
import os
BASE_DIR = config.get('base_dir', '.')
candidates = [
    os.path.join(BASE_DIR, 'SI', f'{order_no}.xlsx'),  # ✅ 路径可配置
]
```

**例外（不修）**：`if __name__ == '__main__':` 块里的自测路径，已由 `os.path.isfile` 守卫的，加注释标记为样本即可。

---

### P-011 日志缺业务上下文
**严重级：P3**
**PEF 对应：F 不可追溯（出了错不知道是哪笔业务出的）**

**查什么**：except 块里的日志是纯文字，没有订单号/批次号/文件名等业务变量。

**怎么判断**：
```python
# ❌ 坏例子：只有异常类型，不知道处理到哪条数据
except Exception as e:
    logger.warning(f'导出失败: {e}')

# ✅ 好例子：带上业务上下文
except Exception as e:
    logger.warning('导出失败[批次=%s, 订单=%s]: %s', batch_id, order_no, e)
```

**为什么重要**：生产环境出问题，日志里只有"导出失败"，你根本不知道是哪个客户、哪批货出的错。F 结果必须能追溯到 (P, E, t)。

---

### P-012 重复 try/close 块
**严重级：P3（语义判断，正则不做）**
**PEF 对应：P 没抽象（同一个主体应该抽成函数，不该复制粘贴）**

**查什么**：同一文件里出现 2 次以上结构几乎一样的 try/close 块。

**坏例子**：
```python
# 573 行
finally:
    if xl is not None:
        try:
            xl.close()
        except Exception:
            pass

# 757 行——一模一样，只是上下文不同
finally:
    if xl is not None:
        try:
            xl.close()
        except Exception:
            pass
```

**好例子**：
```python
def _safe_close(xl):
    if xl is not None:
        try:
            xl.close()
        except OSError:
            pass

# 两处都调 _safe_close(xl)
```

**判断标准**：重复 2 次以内可以接受（YAGNI），重复 3 次以上必须抽函数。

---

### P-014 业务路径用宽 except
**严重级：P2（语义判断，正则不做）**
**PEF 对应：E 没分流（E_in 可预期异常 vs E_out 真 bug，应该分开处理）**

**查什么**：业务主路径（不是辅助路径）用了 `except Exception`。

**怎么区分辅助路径 vs 业务路径**：

| 类型 | 例子 | 应该怎么处理 |
|---|---|---|
| **辅助路径（可以宽）** | close()、设置样式、打日志、删临时文件 | `except Exception` 没问题，不影响主流程 |
| **业务路径（必须窄）** | 数据校验、写入数据库、计算价格、生成发票 | 必须捕获具体异常，或 raise 出去 |

**坏例子**：
```python
# 业务主路径——数据校验
try:
    price = calculate_total(items)
except Exception:  # ❌ 算错了也吞掉，出库金额就错了
    return 0
```

**好例子**：
```python
# 业务路径——真 bug 就让它崩，别吞
try:
    price = calculate_total(items)
except (TypeError, ValueError) as e:
    logger.error('金额计算失败: %s', e)
    raise  # 或者返回明确的错误状态
```

---

## 总结

| 类别 | 规则数 | P0 | P1 | P2 | P3 |
|---|---|---|---|---|---|
| 安全类 | 4 | 3 | 1 | 0 | 0 |
| 错误处理 | 2 | 0 | 1 | 1 | 0 |
| Python 特有 | 3 | 0 | 0 | 2 | 1 |
| 类型空值 | 1 | 0 | 1 | 0 | 0 |
| PEF 结构类 | 4 | 0 | 0 | 2 | 2 |
| **合计** | **14** | **3** | **3** | **5** | **3** |

---

*白盒规则库 v2.0 · 三层审查框架：第一序列建真值 → 第二序列按规则审 → 第三序列防死循环。*
