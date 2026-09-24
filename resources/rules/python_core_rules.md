# Python 核心审查规则库（白盒版）

> 从 bandit 拆解的最常用规则。每条规则白盒写清楚：查什么、怎么判断、例子。
> 作为 bandit 的本地 fallback——bandit 挂了我们自己也能跑。

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

## 总结

| 类别 | 规则数 | P0 | P1 | P2 | P3 |
|---|---|---|---|---|---|
| 安全类 | 4 | 3 | 1 | 0 | 0 |
| 错误处理 | 2 | 0 | 1 | 1 | 0 |
| Python 特有 | 3 | 0 | 0 | 2 | 1 |
| 类型空值 | 1 | 0 | 1 | 0 | 0 |
| **合计** | **10** | **3** | **3** | **3** | **1** |

---

*白盒规则库 v1.0 · 每条规则都知道在查什么、怎么判断。bandit 挂了也能跑。*
