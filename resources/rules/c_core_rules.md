# C 语言核心审查规则库（白盒版）

> 从 Semgrep / cppcheck 拆解的最常用规则。每条规则白盒写清楚：查什么、怎么判断、例子。
> 作为 Semgrep/cppcheck 的本地 fallback——它们挂了我们自己也能跑。

---

## 一、内存安全类（P0/P1）

### C-001 空指针解引用
**严重级：P0**

**查什么**：malloc 返回值没检查就直接用。

**怎么判断**：
```
模式：malloc(...) 后面没有 if (ptr == NULL) 就直接解引用 ptr
```

**坏例子**：
```c
char *buf = malloc(1024);
strcpy(buf, "hello");  // ❌ malloc 失败时 buf=NULL，直接崩溃
```

**好例子**：
```c
char *buf = malloc(1024);
if (buf == NULL) {
    return ERROR_NOMEM;
}
strcpy(buf, "hello");
```

---

### C-002 缓冲区溢出
**严重级：P0**

**查什么**：不安全的字符串函数（strcpy/strcat/sprintf），数组越界访问。

**怎么判断**：
```
模式1：strcpy(buf, input) —— 没检查 input 长度
模式2：strcat(buf, input) —— 同上
模式3：sprintf(buf, fmt, ...) —— 没检查输出长度
模式4：array[i] —— i 没检查边界
```

**坏例子**：
```c
char buf[100];
strcpy(buf, user_input);  // ❌ user_input 超过 100 就溢出
```

**好例子**：
```c
char buf[100];
strncpy(buf, user_input, sizeof(buf) - 1);
buf[sizeof(buf) - 1] = '\0';
```

---

### C-003 内存泄漏
**严重级：P1**

**查什么**：malloc 了没 free，尤其是错误路径。

**怎么判断**：
```
模式：函数里 malloc(ptr)，但所有 return 路径都没有 free(ptr)
```

**坏例子**：
```c
void process_data() {
    char *buf = malloc(1024);
    if (data == NULL) {
        return;  // ❌ 这里直接返回了，buf 没 free
    }
    // ... 处理数据
    free(buf);
}
```

**好例子**：
```c
void process_data() {
    char *buf = malloc(1024);
    if (data == NULL) {
        free(buf);  // ✅ 错误路径也释放
        return;
    }
    // ... 处理数据
    free(buf);
}
```

---

### C-004 双重释放
**严重级：P0**

**查什么**：同一个指针 free 了两次。

**怎么判断**：
```
模式：free(ptr) 后面又出现 free(ptr)，或者函数有多个 return 路径都 free 了同一个指针
```

**坏例子**：
```c
free(buf);
free(buf);  // ❌ 第二次 free 会崩溃
```

**好例子**：
```c
free(buf);
buf = NULL;  // ✅ free 后置 NULL，防止再次 free
```

---

## 二、整数问题类（P1/P2）

### C-005 整数溢出
**严重级：P1**

**查什么**：有符号数运算溢出，无符号数下溢 wrap。

**怎么判断**：
```
模式1：a + b —— 两个正数相加可能溢出成负数
模式2：a * b —— 乘法可能溢出
模式3：uint8_t/uint16_t 递减 —— 到 0 再减就 wrap 到 255/65535
```

**坏例子**：
```c
uint8_t cnt = 0;
cnt--;  // ❌ 0 - 1 = 255，不是 -1
```

**好例子**：
```c
if (cnt > 0) {
    cnt--;
}
```

---

### C-006 未初始化变量
**严重级：P2**

**查什么**：局部变量用之前没初始化。

**怎么判断**：
```
模式：声明了局部变量 int x; 后面直接用 x，没有赋值
```

**坏例子**：
```c
int sum;
for (int i = 0; i < 10; i++) {
    sum += i;  // ❌ sum 没初始化，结果不确定
}
```

**好例子**：
```c
int sum = 0;
for (int i = 0; i < 10; i++) {
    sum += i;
}
```

---

## 三、输入验证类（P1）

### C-007 函数参数未校验
**严重级：P1**

**查什么**：函数参数没检查就用。

**怎么判断**：
```
模式：函数开头没有 if (param == NULL) return; 就直接解引用 param
```

**坏例子**：
```c
void set_name(User *u, char *name) {
    strcpy(u->name, name);  // ❌ u 或 name 是 NULL 就崩溃
}
```

**好例子**：
```c
void set_name(User *u, char *name) {
    if (u == NULL || name == NULL) return;
    strncpy(u->name, name, sizeof(u->name) - 1);
}
```

---

### C-008 除零风险
**严重级：P0**

**查什么**：除法运算前没检查除数是不是 0。

**怎么判断**：
```
模式：result = a / b; —— b 没检查是不是 0
```

**坏例子**：
```c
float avg = total / count;  // ❌ count=0 就崩溃
```

**好例子**：
```c
if (count == 0) {
    avg = 0;
} else {
    avg = total / count;
}
```

---

## 四、时序与并发类（P0/P1）

### C-009 竞态条件
**严重级：P0**

**查什么**：ISR 和主循环共享变量，没加保护。

**怎么判断**：
```
模式：全局变量在 ISR 里写，在主循环里读，没有临界区保护
```

**坏例子**：
```c
volatile int flag = 0;

void ISR() {
    flag = 1;
}

void main_loop() {
    if (flag) {
        // 处理中断  // ❌ flag 可能在判断的瞬间被 ISR 改了
    }
}
```

**好例子**：
```c
// 关中断，读 flag，再开中断
__disable_irq();
int local_flag = flag;
flag = 0;
__enable_irq();
```

---

### C-010 返回局部变量地址
**严重级：P0**

**查什么**：函数返回局部变量的指针。

**怎么判断**：
```
模式：函数里 int x; return &x; —— x 在栈上，函数返回后就销毁了
```

**坏例子**：
```c
int *get_value() {
    int x = 42;
    return &x;  // ❌ x 在栈上，函数返回后指针失效
}
```

**好例子**：
```c
int get_value() {
    int x = 42;
    return x;  // ✅ 返回值拷贝
}
```

---

## 五、其他（P2/P3）

### C-011 goto 滥用
**严重级：P3**

**查什么**：goto 用得太多，代码跳来跳去。

---

### C-012 魔法数字
**严重级：P3**

**查什么**：代码里写死的数字，没有命名。

---

## 总结

| 类别 | 规则数 | P0 | P1 | P2 | P3 |
|---|---|---|---|---|---|
| 内存安全 | 4 | 3 | 1 | 0 | 0 |
| 整数问题 | 2 | 0 | 1 | 1 | 0 |
| 输入验证 | 2 | 1 | 1 | 0 | 0 |
| 时序并发 | 2 | 2 | 0 | 0 | 0 |
| 其他 | 2 | 0 | 0 | 0 | 2 |
| **合计** | **12** | **6** | **3** | **1** | **2** |

---

*白盒规则库 v1.0 · 每条规则都知道在查什么、怎么判断。Semgrep/cppcheck 挂了也能跑。*
