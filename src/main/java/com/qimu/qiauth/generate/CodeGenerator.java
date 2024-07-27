package com.qimu.qiauth.generate;

import com.qimu.qiauth.model.entity.Post;
import com.qimu.qiauth.model.entity.User;

/**
 * 代码生成器
 *
 * @author <a href="https://github.com/liyupi">程序员鱼皮</a>
 * @from <a href="https://www.code-nav.cn">编程导航学习圈</a>
 */
public class CodeGenerator {

    /**
     * 用法：追加process(数据类.class, "数据别名");
     */
    public static void main(String[] args) {
        // 代码生成处理器
        new GenerateProcessor()
                // 生成项目路径
                .packageName("com.qimu.qiauth")
                // 排除字段策略
                .exclusionStrategy("serialVersionUID", "isDelete")
                .process(Post.class, "帖子")
                .process(User.class, "用户");
        // ..继续追加process(数据类.class, "数据别名");
    }
}
