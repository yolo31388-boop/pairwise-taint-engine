# pairwise-taint-engine

代码审计平台一扫，跨文件的污点路径全断：Java 的 source 只识别 Servlet 参数，Spring 的 @RequestParam 和 Kotlin 扩展函数漏报；sanitizer 只按方法名匹配，同名自定义 escape 被误当安全；字段赋值和容器元素没有传播，污点进 List 后消失；分支合并时用了交集而不是并集，条件里的漏报；lambda 和匿名类捕获变量没有建边；规则命中后没有最短路径，报告里给出 200 跳的噪声链。security/taint_engine.py 是核心，tests/test_taint_engine.py 15个红。要修的是：框架 source 建模；sanitizer 白名单带签名；字段/容器传播；分支并集；闭包捕获；最短路径。

## 运行

```bash
python -m pytest tests -q
```

初始状态：15 个用例失败。修复实现使全部用例通过，不要修改 `tests/` 下的测试。

子方向：漏洞检测与攻防；任务类型：Bugfix；语言/框架：Python 3, pytest；环境可复现等级：无外部依赖。
