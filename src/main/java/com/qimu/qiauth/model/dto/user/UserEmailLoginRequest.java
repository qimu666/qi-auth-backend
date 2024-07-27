package com.qimu.qiauth.model.dto.user;

import lombok.Data;

import java.io.Serializable;

/**
 * @Author: QiMu
 * @Date: 2023/09/04 11:34:06
 * @Version: 1.0
 * @Description: 用户登录请求体
 */
@Data
public class UserEmailLoginRequest implements Serializable {

    private static final long serialVersionUID = 3191241716373120793L;

    /**
     * 电子邮件帐户
     */
    private String emailAccount;

    /**
     * 验证码
     */
    private String captcha;
}
