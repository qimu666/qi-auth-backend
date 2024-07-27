package ${packageName}.model.dto.${dataKey};

import lombok.Data;

import java.io.Serializable;
import java.util.List;

/**
 * 编辑${dataName}请求
 *
 * @author <a href="https://github.com/liyupi">程序员鱼皮</a>
 * @from <a href="https://www.code-nav.cn">编程导航学习圈</a>
 */
@Data
public class ${upperDataKey}EditRequest implements Serializable {

    ${field}
    private static final long serialVersionUID = 1L;
}