package com.qimu.qiauth.common;

/**
 * 自定义错误码
 *
 * @author <a href="https://github.com/liyupi">程序员鱼皮</a>
 * @from <a href="https://yupi.icu">编程导航知识星球</a>
 */
public enum ErrorCode {

    /**
     * 成功
     */
    SUCCESS(0, "ok"),
    /**
     * 请求过于频繁
     */
    TOO_MANY_REQUEST(42900, "请求过于频繁"),
    /**
     * 账号已封禁
     */
    PROHIBITED(40001, "账号已封禁"),
    /**
     * 请求参数错误
     */
    PARAMS_ERROR(40000, "请求参数错误"),
    /**
     * 未登录
     */
    NOT_LOGIN_ERROR(40100, "未登录"),
    /**
     * 无权限
     */
    NO_AUTH_ERROR(40101, "无权限"),
    /**
     * 请求数据不存在
     */
    NOT_FOUND_ERROR(40400, "请求数据不存在"),
    /**
     * 禁止访问
     */
    FORBIDDEN_ERROR(40300, "禁止访问"),
    /**
     * 系统错误
     */
    SYSTEM_ERROR(50000, "系统内部异常"),
    /**
     * 操作错误
     */
    OPERATION_ERROR(50001, "操作失败");
    /**
     * 状态码
     */
    private final int code;

    /**
     * 信息
     */
    private final String message;

    ErrorCode(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }

}
