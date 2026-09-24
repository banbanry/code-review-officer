"""
L6 探针校准测试集

参考 bandit 官方测试用例设计，用 bandit 当金标准来校准我们自己的 L6 探针。
10 个真 bug（应该报）+ 10 个假 bug（不应该报）。
"""

# ========== 真 bug（应该被检出）==========

TRUE_POSITIVES = [
    {
        "id": "TP-001",
        "severity": "p0",
        "category": "CODE_INJECTION",
        "code": """
import os
user_input = request.args.get('cmd')
os.system(f"ls {user_input}")
""",
        "expected": "命令注入",
    },
    {
        "id": "TP-002",
        "severity": "p0",
        "category": "EVAL_INJECTION",
        "code": """
user_input = request.args.get('expr')
result = eval(user_input)
""",
        "expected": "eval 代码注入",
    },
    {
        "id": "TP-003",
        "severity": "p1",
        "category": "HARDCODED_SECRET",
        "code": """
API_KEY = "sk-72e8c8e29bc74072868a3359a640ab1b"
""",
        "expected": "硬编码 API key",
    },
    {
        "id": "TP-004",
        "severity": "p1",
        "category": "SILENT_EXCEPT",
        "code": """
try:
    db.commit()
except Exception:
    pass
""",
        "expected": "静默吞错",
    },
    {
        "id": "TP-005",
        "severity": "p0",
        "category": "PICKLE_DESERIALIZE",
        "code": """
import pickle
data = pickle.loads(request.body)
""",
        "expected": "pickle 反序列化漏洞",
    },
    {
        "id": "TP-006",
        "severity": "p2",
        "category": "MUTABLE_DEFAULT",
        "code": """
def add_item(item, lst=[]):
    lst.append(item)
    return lst
""",
        "expected": "可变默认参数",
    },
    {
        "id": "TP-007",
        "severity": "p1",
        "category": "ASSERT_USAGE",
        "code": """
def login(user):
    assert user.is_authenticated
    # 生产环境 assert 会被关掉
""",
        "expected": "assert 用于生产验证",
    },
    {
        "id": "TP-008",
        "severity": "p2",
        "category": "WEAK_HASH",
        "code": """
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()
""",
        "expected": "弱哈希算法 MD5",
    },
    {
        "id": "TP-009",
        "severity": "p1",
        "category": "SUBPROCESS_SHELL",
        "code": """
import subprocess
subprocess.run("ls " + filename, shell=True)
""",
        "expected": "subprocess shell=True",
    },
    {
        "id": "TP-010",
        "severity": "p2",
        "category": "TMP_PATH_PREDICTABLE",
        "code": """
import tempfile
tmp = "/tmp/user_data.txt"  #  predictable 路径
""",
        "expected": "可预测的临时文件路径",
    },
]


# ========== 假 bug（不应该被检出）==========

FALSE_POSITIVES = [
    {
        "id": "FP-001",
        "code": """
import ast
data = ast.literal_eval(user_input)  # 安全的，不是 eval
""",
        "expected": "不应该报 eval 注入",
    },
    {
        "id": "FP-002",
        "code": """
# 这是注释：os.system("ls -la")
# 注释里的代码不应该被扫到
""",
        "expected": "不应该报注释里的代码",
    },
    {
        "id": "FP-003",
        "code": """
import hashlib
# 用 MD5 做文件校验和，不是做密码哈希
checksum = hashlib.md5(file_bytes).hexdigest()
""",
        "expected": "不应该报弱哈希（校验和是合法用途）",
    },
    {
        "id": "FP-004",
        "code": """
try:
    db.commit()
except Exception as e:
    logger.error(f"提交失败: {e}")  # 有日志，不是静默
    raise
""",
        "expected": "不应该报静默吞错（有日志）",
    },
    {
        "id": "FP-005",
        "code": """
import os
# 固定参数，没有用户输入
subprocess.run(["ls", "-la"], shell=False)
""",
        "expected": "不应该报命令注入（没有用户输入）",
    },
    {
        "id": "FP-006",
        "code": """
import json
data = json.loads(request.body)  # JSON 是安全的
""",
        "expected": "不应该报反序列化（json 安全）",
    },
    {
        "id": "FP-007",
        "code": """
def add_item(item, lst=None):
    if lst is None:
        lst = []  # 正确的写法
    lst.append(item)
    return lst
""",
        "expected": "不应该报可变默认参数",
    },
    {
        "id": "FP-008",
        "code": """
API_KEY = os.environ.get("API_KEY")  # 从环境变量读
""",
        "expected": "不应该报硬编码密钥",
    },
    {
        "id": "FP-009",
        "code": """
# nosec: B603 - 这是测试代码，允许 shell=True
import subprocess
subprocess.run("echo hello", shell=True)  # nosec
""",
        "expected": "不应该报有 nosec 标记的",
    },
    {
        "id": "FP-010",
        "code": """
if user is not None:  # 已经判空了
    print(user.name)
""",
        "expected": "不应该报空指针（已经判空）",
    },
]


# ========== C 语言用例（参考 cppcheck 典型规则）==========

C_TRUE_POSITIVES = [
    {
        "id": "TP-C01",
        "severity": "p0",
        "category": "NULL_DEREF",
        "code": """
#include <stdlib.h>
void func() {
    char *buf = malloc(1024);
    strcpy(buf, "hello");
}
""",
        "expected": "空指针解引用（malloc 没判空）",
    },
    {
        "id": "TP-C02",
        "severity": "p0",
        "category": "BUFFER_OVERFLOW",
        "code": """
void func(char *input) {
    char buf[100];
    strcpy(buf, input);
}
""",
        "expected": "缓冲区溢出（strcpy）",
    },
    {
        "id": "TP-C03",
        "severity": "p1",
        "category": "MEMORY_LEAK",
        "code": """
void func() {
    char *buf = malloc(1024);
    if (data == NULL) {
        return;
    }
    free(buf);
}
""",
        "expected": "内存泄漏（错误路径没释放）",
    },
    {
        "id": "TP-C04",
        "severity": "p0",
        "category": "DIV_ZERO",
        "code": """
float avg(float total, int count) {
    return total / count;
}
""",
        "expected": "除零风险",
    },
    {
        "id": "TP-C05",
        "severity": "p1",
        "category": "UNINITIALIZED_VAR",
        "code": """
int sum() {
    int sum;
    for (int i = 0; i < 10; i++) {
        sum += i;
    }
    return sum;
}
""",
        "expected": "未初始化变量",
    },
    {
        "id": "TP-C06",
        "severity": "p0",
        "category": "DOUBLE_FREE",
        "code": """
void func() {
    char *buf = malloc(1024);
    free(buf);
    free(buf);
}
""",
        "expected": "双重释放",
    },
    {
        "id": "TP-C07",
        "severity": "p1",
        "category": "UNSIGNED_UNDERFLOW",
        "code": """
void decrement(uint8_t *cnt) {
    (*cnt)--;
}
""",
        "expected": "无符号下溢",
    },
    {
        "id": "TP-C08",
        "severity": "p0",
        "category": "RETURN_LOCAL_ADDR",
        "code": """
int* get_value() {
    int x = 42;
    return &x;
}
""",
        "expected": "返回局部变量地址",
    },
    {
        "id": "TP-C09",
        "severity": "p1",
        "category": "FORMAT_STRING",
        "code": """
void log_msg(char *user_input) {
    printf(user_input);
}
""",
        "expected": "格式化字符串漏洞",
    },
    {
        "id": "TP-C10",
        "severity": "p0",
        "category": "RACE_CONDITION",
        "code": """
volatile int flag = 0;
void ISR() { flag = 1; }
void main_loop() {
    if (flag) {
        // handle
    }
}
""",
        "expected": "竞态条件（ISR 与主循环共享变量）",
    },
]


C_FALSE_POSITIVES = [
    {
        "id": "FP-C01",
        "code": """
#include <stdlib.h>
void func() {
    char *buf = malloc(1024);
    if (buf == NULL) {
        return;
    }
    strcpy(buf, "hello");
}
""",
        "expected": "不应该报空指针（已经判空）",
    },
    {
        "id": "FP-C02",
        "code": """
void func(char *input) {
    char buf[100];
    strncpy(buf, input, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\\0';
}
""",
        "expected": "不应该报缓冲区溢出（用了 strncpy）",
    },
    {
        "id": "FP-C03",
        "code": """
// strcpy(buf, input);  // 这是注释里的
""",
        "expected": "不应该报注释里的代码",
    },
    {
        "id": "FP-C04",
        "code": """
float avg(float total, int count) {
    if (count == 0) return 0;
    return total / count;
}
""",
        "expected": "不应该报除零（已经检查了）",
    },
    {
        "id": "FP-C05",
        "code": """
int sum() {
    int sum = 0;
    for (int i = 0; i < 10; i++) {
        sum += i;
    }
    return sum;
}
""",
        "expected": "不应该报未初始化变量",
    },
    {
        "id": "FP-C06",
        "code": """
void func() {
    char *buf = malloc(1024);
    free(buf);
    buf = NULL;
    free(buf);
}
""",
        "expected": "不应该报双重释放（free 后置了 NULL）",
    },
    {
        "id": "FP-C07",
        "code": """
void decrement(uint8_t *cnt) {
    if (*cnt > 0) {
        (*cnt)--;
    }
}
""",
        "expected": "不应该报无符号下溢（已经检查了）",
    },
    {
        "id": "FP-C08",
        "code": """
int get_value() {
    int x = 42;
    return x;
}
""",
        "expected": "不应该报返回局部变量地址",
    },
    {
        "id": "FP-C09",
        "code": """
void log_msg(const char *msg) {
    printf("Received: %s", msg);
}
""",
        "expected": "不应该报格式化字符串（格式串固定）",
    },
    {
        "id": "FP-C10",
        "code": """
int a = 5 / 2;
""",
        "expected": "不应该报除零（常量除法）",
    },
]


def run_calibration(scanner_func) -> dict:
    """
    跑校准测试：
    - scanner_func: 接收代码字符串，返回发现列表
    - 返回：召回率、准确率、误报数
    """
    tp_count = 0
    fp_count = 0
    fn_count = 0

    print("=" * 60)
    print("L6 探针校准测试")
    print("=" * 60)

    print("\n--- 真 bug 测试（应该检出）---")
    for tp in TRUE_POSITIVES:
        findings = scanner_func(tp["code"])
        if findings:
            tp_count += 1
            print(f'  ✅ {tp["id"]} 检出：{tp["expected"]}')
        else:
            fn_count += 1
            print(f'  ❌ {tp["id"]} 漏检：{tp["expected"]}')

    print("\n--- 假 bug 测试（不应该检出）---")
    for fp in FALSE_POSITIVES:
        findings = scanner_func(fp["code"])
        if findings:
            fp_count += 1
            print(f'  ⚠️  {fp["id"]} 误报：{fp["expected"]}（报了 {len(findings)} 条）')
        else:
            print(f'  ✅ {fp["id"]} 正确：{fp["expected"]}')

    # 算指标
    total_tp = len(TRUE_POSITIVES)
    total_fp = len(FALSE_POSITIVES)
    recall = tp_count / total_tp if total_tp > 0 else 0
    precision = tp_count / (tp_count + fp_count) if (tp_count + fp_count) > 0 else 0

    print("\n" + "=" * 60)
    print(f"召回率（真 bug 抓到多少）: {recall:.1%} ({tp_count}/{total_tp})")
    print(f"准确率（报的里有多少真的）: {precision:.1%} ({tp_count}/{tp_count+fp_count})")
    print(f"误报数（假 bug 报了多少）: {fp_count}/{total_fp}")
    print("=" * 60)

    return {
        "recall": recall,
        "precision": precision,
        "true_positives": tp_count,
        "false_negatives": fn_count,
        "false_positives": fp_count,
    }


if __name__ == "__main__":
    # 测试用：用 local_rules.py 当 scanner
    import sys
    sys.path.insert(0, "..")
    from local_rules import scan_file
    import tempfile
    import os

    def temp_scanner(code: str) -> list:
        """把代码写到临时文件，用 local_rules 扫"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False, encoding='utf-8') as f:
            f.write(code)
            tmpfile = f.name
        try:
            return scan_file(tmpfile)
        finally:
            os.unlink(tmpfile)

    result = run_calibration(temp_scanner)
